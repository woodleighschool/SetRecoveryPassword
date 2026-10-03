package jamf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
)

const managementID = "aaaaaaaa-3f1e-4b3a-a5b3-ca0cd7430937"
const commandID = "bbbbbbbb-3f1e-4b3a-a5b3-ca0cd7430937"

var testDevice = Device{ID: 7, Name: "Test Mac", ManagementID: managementID}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/oauth/token" {
			_, _ = io.WriteString(w, `{"access_token":"test","expires_in":3600,"token_type":"Bearer"}`)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(&config.Config{InstanceDomain: server.URL, ClientID: "test", ClientSecret: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestComputersUsesSDKPaginationAndFilters(t *testing.T) {
	var pages []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/computers-inventory" {
			t.Errorf("path %s", r.URL.Path)
		}
		q := r.URL.Query()
		if !strings.Contains(q.Get("filter"), "hardware.appleSilicon==true") || q.Get("section") != "GENERAL,HARDWARE" {
			t.Error("missing inventory filter or sections")
		}
		pages = append(pages, q.Get("page"))
		if q.Get("page") == "0" {
			_, _ = fmt.Fprintf(w, `{"totalCount":201,"results":[{"id":"7","general":{"name":"Test Mac","managementId":%q,"remoteManagement":{"managed":true}},"hardware":{"appleSilicon":true}}]}`, managementID)
		} else {
			_, _ = fmt.Fprintf(w, `{"totalCount":201,"results":[{"id":"8","general":{"remoteManagement":{"managed":true}},"hardware":{"appleSilicon":false}}]}`)
		}
	})
	computers, err := client.Computers(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(computers) != 1 || computers[0] != testDevice {
		t.Fatalf("computers %#v", computers)
	}
	if strings.Join(pages, ",") != "0,1" {
		t.Fatalf("pages %#v", pages)
	}
}

func TestPasswordUsesCurrentEndpoint(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/computers-inventory/7/view-recovery-lock-password" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"recoveryLockPassword":"confirmed"}`)
	})
	password, err := client.Password(t.Context(), testDevice)
	if err != nil || password != "confirmed" {
		t.Fatalf("password %q err %v", password, err)
	}
}

func TestQueuePayloadAndSingleUUID(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		ok         bool
	}{
		{"valid", `[{"id":"` + commandID + `","href":"/api/v2/mdm/commands/` + commandID + `"}]`, 201, true},
		{"empty", `[]`, 201, false}, {"invalid UUID", `[{"id":"7"}]`, 201, false},
		{"multiple", `[{"id":"` + commandID + `"},{"id":"` + commandID + `"}]`, 201, false},
		{"SDK incorrect object", `{"id":"` + commandID + `"}`, 201, false},
		{"server failure", `{"message":"candidate secret must never be logged"}`, 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes atomic.Int32
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, `{"totalCount":0,"results":[]}`)
					return
				}
				writes.Add(1)
				var payload struct {
					CommandData map[string]string   `json:"commandData"`
					ClientData  []map[string]string `json:"clientData"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if payload.CommandData["newPassword"] != "candidate" || payload.CommandData["commandType"] != "SET_RECOVERY_LOCK" || len(payload.ClientData) != 1 || payload.ClientData[0]["managementId"] != managementID {
					t.Errorf("incorrect queue payload")
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			})
			id, err := client.Queue(t.Context(), testDevice, "candidate")
			if (err == nil) != tc.ok {
				t.Fatalf("id %q err %v", id, err)
			}
			if tc.ok && id != commandID {
				t.Fatalf("id %q", id)
			}
			if err != nil && strings.Contains(err.Error(), "candidate secret") {
				t.Fatal("leaked response")
			}
			if writes.Load() != 1 {
				t.Fatalf("POST replayed %d times", writes.Load())
			}
		})
	}
}

func TestCommandStatesAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, fields, want string
		fail               bool
	}{
		{"titlecase pending", `"status":"Pending"`, "pending", false},
		{"acknowledged", `"status":"Acknowledged"`, "acknowledged", false},
		{"failed", `"status":"Failed"`, "failed", false},
		{"published shape", `"commandState":"ERROR","commandError":{"errorCode":1,"errorEnglishDescription":"The provided recovery password failed to validate."}`, "failed", false},
		{"not now", `"commandState":"NOT_NOW"`, "pending", false},
		{"empty error object", `"status":"Acknowledged","commandError":{}`, "acknowledged", false},
		{"future status", `"status":"NewUnknownStatus"`, "unknown", false},
		{"contradiction", `"status":"Acknowledged","commandState":"ERROR"`, "", true},
		{"wrong device", `"status":"Acknowledged","client":{"managementId":"cccccccc-3f1e-4b3a-a5b3-ca0cd7430937"}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("filter") != "clientManagementId=="+managementID+";uuid=="+commandID {
					t.Error("UUID/device filter missing")
				}
				_, _ = fmt.Fprintf(w, `{"totalCount":1,"results":[{"uuid":%q,"commandType":"SET_RECOVERY_LOCK",%s}]}`, commandID, tc.fields)
			})
			command, err := client.Command(t.Context(), testDevice, commandID)
			if (err != nil) != tc.fail || (!tc.fail && command.Status != tc.want) {
				t.Fatalf("command %#v err %v", command, err)
			}
			if tc.name == "published shape" && command.Detail != "The provided recovery password failed to validate." {
				t.Error("lost diagnostic")
			}
		})
	}
}

func TestCommandsExposeOtherPendingRotation(t *testing.T) {
	var writes atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter"); got != "clientManagementId=="+managementID+";command=in=(SET_RECOVERY_LOCK,VERIFY_RECOVERY_LOCK)" {
			t.Errorf("unsupported recovery history filter: %s", got)
		}
		if r.Method == http.MethodPost {
			writes.Add(1)
		}
		_, _ = fmt.Fprintf(w, `{"totalCount":1,"results":[{"uuid":%q,"commandType":"SET_RECOVERY_LOCK","status":"Pending"}]}`, commandID)
	})
	if commands, err := client.Commands(t.Context(), testDevice); err != nil || len(commands) != 1 || commands[0].Status != "pending" {
		t.Fatal("pending history not recognized")
	}
	if writes.Load() != 0 {
		t.Fatal("queued despite pending rotation")
	}
}

func TestCancellationPreventsQueue(t *testing.T) {
	var writes atomic.Int32
	client := testClient(t, func(_ http.ResponseWriter, _ *http.Request) { writes.Add(1) })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := client.Queue(ctx, testDevice, "candidate")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if writes.Load() != 0 {
		t.Fatal("request made after cancellation")
	}
}

func TestQueueDoesNotReplayAfterResponseLoss(t *testing.T) {
	var writes atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"totalCount":0,"results":[]}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		writes.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	})
	if _, err := client.Queue(t.Context(), testDevice, "candidate"); err == nil {
		t.Fatal("lost response accepted as success")
	}
	if writes.Load() != 1 {
		t.Fatalf("ambiguous command replayed %d times", writes.Load())
	}
}

func TestCommandRetainsSubmissionTimestamp(t *testing.T) {
	for _, tc := range []struct {
		timestamp string
		fail      bool
	}{
		{timestamp: "2026-10-01T00:00:00.123Z"},
		{timestamp: ""},
		{timestamp: "not-a-date", fail: true},
	} {
		t.Run(tc.timestamp, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"totalCount":1,"results":[{"uuid":%q,"commandType":"SET_RECOVERY_LOCK","commandState":"ACKNOWLEDGED","dateSent":%q}]}`, commandID, tc.timestamp)
			})
			command, err := client.Command(t.Context(), testDevice, commandID)
			if (err != nil) != tc.fail {
				t.Fatalf("command=%+v err=%v", command, err)
			}
			if err == nil && command.SentAt.IsZero() != (tc.timestamp == "") {
				t.Fatal("lost command timestamp")
			}
		})
	}
}

func TestCommandHistoryMustBeCompleteAndUnique(t *testing.T) {
	for _, tc := range []struct {
		name      string
		total     int
		duplicate bool
		fail      bool
	}{
		{name: "complete", total: 2},
		{name: "incomplete", total: 3, fail: true},
		{name: "duplicate", total: 2, duplicate: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				second := "cccccccc-3f1e-4b3a-a5b3-ca0cd7430937"
				if tc.duplicate {
					second = commandID
				}
				_, _ = fmt.Fprintf(w, `{"totalCount":%d,"results":[{"uuid":%q,"commandType":"SET_RECOVERY_LOCK","commandState":"ACKNOWLEDGED"},{"uuid":%q,"commandType":"SET_RECOVERY_LOCK","commandState":"PENDING"}]}`, tc.total, commandID, second)
			})
			_, err := client.Commands(t.Context(), testDevice)
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCommandHistoryIncludesUnsettledCommandsOnLaterPages(t *testing.T) {
	var pages []string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		size, err := strconv.Atoi(r.URL.Query().Get("page-size"))
		if err != nil || size < 1 {
			t.Error("missing pagination size")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var records []map[string]string
		if page == "0" {
			for i := range size {
				records = append(records, map[string]string{
					"uuid":         fmt.Sprintf("%08x-3f1e-4b3a-a5b3-ca0cd7430937", i+1),
					"commandType":  "SET_RECOVERY_LOCK",
					"commandState": "ACKNOWLEDGED",
				})
			}
		} else {
			records = append(records, map[string]string{
				"uuid": commandID, "commandType": "SET_RECOVERY_LOCK", "commandState": "PENDING",
			})
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"totalCount": size + 1, "results": records}); err != nil {
			t.Error(err)
		}
	})
	commands, err := client.Commands(t.Context(), testDevice)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pages, ",") != "0,1" || len(commands) < 2 || commands[len(commands)-1].Status != "pending" {
		t.Fatal("later pending command omitted from history")
	}
}
