package onepasswordsdk

import (
	"context"
	"errors"
	"testing"

	"github.com/1password/onepassword-sdk-go"
	"github.com/woodleighschool/jamf-recovery-lock/internal/jamf"
)

type fakeItems struct {
	overviews []onepassword.ItemOverview
	item      onepassword.Item
	creates   int
	puts      int
	seenCtx   context.Context
}

func (f *fakeItems) List(ctx context.Context, _ string, _ ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error) {
	f.seenCtx = ctx
	return f.overviews, ctx.Err()
}
func (f *fakeItems) Get(ctx context.Context, _, _ string) (onepassword.Item, error) {
	f.seenCtx = ctx
	return f.item, ctx.Err()
}
func (f *fakeItems) Put(ctx context.Context, item onepassword.Item) (onepassword.Item, error) {
	f.seenCtx = ctx
	f.puts++
	f.item = item
	return item, ctx.Err()
}
func (f *fakeItems) Create(ctx context.Context, params onepassword.ItemCreateParams) (onepassword.Item, error) {
	f.seenCtx = ctx
	f.creates++
	f.item = onepassword.Item{ID: "new-item", Fields: params.Fields, Tags: params.Tags}
	return f.item, ctx.Err()
}
func concealed(id, title, value string) onepassword.ItemField {
	return onepassword.ItemField{ID: id, Title: title, Value: value, FieldType: onepassword.ItemFieldTypeConcealed}
}

func TestUpdateUsesFieldIDAndPreservesOtherFields(t *testing.T) {
	items := &fakeItems{item: onepassword.Item{ID: "existing", Fields: []onepassword.ItemField{concealed("password", "Renamed password", "old"), concealed("other", "password", "keep")}}}
	client := &Client{items: items, vaultID: "vault"}
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "context")
	if err := client.UpdateSecret(ctx, "existing", "confirmed"); err != nil {
		t.Fatal(err)
	}
	if items.item.Fields[0].Value != "confirmed" || items.item.Fields[1].Value != "keep" || items.seenCtx != ctx {
		t.Fatal("incorrect field or context")
	}
}
func TestMissingPasswordIDDoesNotWrite(t *testing.T) {
	items := &fakeItems{item: onepassword.Item{Fields: []onepassword.ItemField{concealed("other", "password", "keep")}}}
	if err := (&Client{items: items}).UpdateSecret(t.Context(), "existing", "confirmed"); err == nil {
		t.Fatal("missing field accepted")
	}
	if items.puts != 0 {
		t.Fatal("item overwritten without password field")
	}
}
func TestCreateRecoversUnpersistedUUID(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		title := "Test Mac (7) - Recovery Password"
		tags := []string(nil)
		if renamed {
			title = "Old name"
			tags = []string{"jamf-recovery-lock", "jamf-computer-id:7"}
		}
		items := &fakeItems{overviews: []onepassword.ItemOverview{{ID: "existing", Title: title, Tags: tags}}, item: onepassword.Item{Fields: []onepassword.ItemField{concealed("password", "password", "confirmed")}}}
		id, err := (&Client{items: items, vaultID: "vault"}).CreateSecret(t.Context(), jamf.Device{ID: 7, Name: "New name"}, "confirmed")
		if err != nil || id != "existing" || items.creates != 0 {
			t.Fatalf("id %q error %v creates %d", id, err, items.creates)
		}
	}
}
func TestCreateBlocksAmbiguousOrDifferentExistingSecret(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		items := &fakeItems{overviews: []onepassword.ItemOverview{{ID: "existing", Title: "Test (7) - Recovery Password"}}, item: onepassword.Item{Fields: []onepassword.ItemField{concealed("password", "password", "known-good")}}}
		if duplicate {
			items.overviews = append(items.overviews, items.overviews[0])
		}
		_, err := (&Client{items: items}).CreateSecret(t.Context(), jamf.Device{ID: 7}, "candidate")
		if err == nil || items.creates != 0 {
			t.Fatal("created duplicate or ignored conflict")
		}
	}
}
func TestCreateNewItemTagsAndCancellation(t *testing.T) {
	items := &fakeItems{}
	client := &Client{items: items, vaultID: "vault"}
	id, err := client.CreateSecret(t.Context(), jamf.Device{ID: 7, Name: "Test"}, "confirmed")
	if err != nil || id != "new-item" || len(items.item.Tags) != 2 || items.item.Fields[0].Value != "confirmed" {
		t.Fatalf("id %q error %v", id, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.CreateSecret(ctx, jamf.Device{ID: 8}, "candidate")
	if !errors.Is(err, context.Canceled) || items.creates != 1 {
		t.Fatal("cancellation ignored")
	}
}
