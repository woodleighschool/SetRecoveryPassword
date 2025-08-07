# SetRecoveryPassword

A Python application that sets random recovery passwords for modern macOS devices via the Jamf API and stores them securely in 1Password.

## Features

-   Authenticates with Jamf Pro API using OAuth2 client credentials
-   Generates random recovery passwords for macOS devices
-   Temporarily stores passwords in a local SQLite database until Jamf API reflects changes
-   Securely stores passwords in 1Password using service account integration
-   Automatically rotates passwords on a configurable schedule (default: monthly)
-   Supports scheduled updates using cron expressions
-   Configurable logging levels
-   Can run as a one-time update or scheduled background process
-   Dry run mode for testing without making changes

## Installation

### Option 1: From GitHub Release

Download the wheel file from the [latest release](https://github.com/woodleighschool/SetRecoveryPassword/releases) and install:

```bash
pip3 install setrecoverypassword-*.whl
```

### Option 2: From Source

1. Clone the repository:

```bash
git clone https://github.com/woodleighschool/SetRecoveryPassword.git
cd SetRecoveryPassword
```

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Or install the package:

```bash
pip3 install .
```

### Option 3: Direct from GitHub

```bash
# Install latest release
pip3 install git+https://github.com/woodleighschool/SetRecoveryPassword.git

# Install specific version
pip3 install git+https://github.com/woodleighschool/SetRecoveryPassword.git@v1.0.0
```

## Configuration

The application uses environment variables for configuration:

| Variable             | Description                                         | Required | Default                         |
| -------------------- | --------------------------------------------------- | -------- | ------------------------------- |
| `JAMF_HOST`          | Your Jamf Pro server hostname                       | Yes      | -                               |
| `JAMF_CLIENT_ID`     | OAuth2 client ID                                    | Yes      | -                               |
| `JAMF_CLIENT_SECRET` | OAuth2 client secret                                | Yes      | -                               |
| `VAULT_ID`           | 1Password vault ID                                  | Yes      | -                               |
| `ONEPASSWORD_TOKEN`  | 1Password service account token                     | Yes      | -                               |
| `UPDATE_NOW`         | Run update immediately (`true`/`false`)             | No       | `false`                         |
| `UPDATE_SCHEDULE`    | Cron schedule for updates                           | No       | `0 0 * * *` (daily at midnight) |
| `DRY_RUN`            | Run without making changes (`true`/`false`)         | No       | `false`                         |
| `DB_PATH`            | Path to the SQLite database file                    | No       | `./state.db`                    |
| `LOG_LEVEL`          | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | No       | `INFO`                          |

## Usage

### Command Line

```bash
# Run once
JAMF_HOST="jamf.example.com" \
JAMF_CLIENT_ID="your-client-id" \
JAMF_CLIENT_SECRET="your-client-secret" \
VAULT_ID="your-vault-id" \
ONEPASSWORD_TOKEN="your-token" \
UPDATE_NOW=true \
python3 setrecoverypassword.py

# Run with scheduled updates (daily at 2 AM)
JAMF_HOST="jamf.example.com" \
JAMF_CLIENT_ID="your-client-id" \
JAMF_CLIENT_SECRET="your-client-secret" \
VAULT_ID="your-vault-id" \
ONEPASSWORD_TOKEN="your-token" \
UPDATE_SCHEDULE="0 2 * * *" \
python3 setrecoverypassword.py

# Dry run mode (test without making changes)
JAMF_HOST="jamf.example.com" \
JAMF_CLIENT_ID="your-client-id" \
JAMF_CLIENT_SECRET="your-client-secret" \
VAULT_ID="your-vault-id" \
ONEPASSWORD_TOKEN="your-token" \
DRY_RUN=true \
UPDATE_NOW=true \
python3 setrecoverypassword.py
```

### As an Installed Package

```bash
# After pip install
JAMF_HOST="jamf.example.com" \
JAMF_CLIENT_ID="your-client-id" \
JAMF_CLIENT_SECRET="your-client-secret" \
VAULT_ID="your-vault-id" \
ONEPASSWORD_TOKEN="your-token" \
setrecoverypassword
```

## Jamf Pro API Setup

1. In Jamf Pro, go to Settings > System Settings > API Roles and Privileges
2. Create a new role with the following privileges:
    - Computers: Read, Update
    - Recovery Lock Password: Read
    - Send Computer Remote Command to Set Recovery Lock: Create
3. Go to Settings > System Settings > API Integrations and Credentials
4. Create a new API Client with the role created above
5. Note the Client ID and Client Secret for configuration

## 1Password Setup

1. Create a service account in your 1Password account
2. Grant the service account access to the vault where you want to store recovery passwords
3. Generate a service account token
4. Note the Vault ID and service account token for configuration

## How It Works

1. **Initial Setup**: The application fetches all managed macOS devices from Jamf Pro
2. **Password Generation**: For new devices or expired passwords (>30 days), generates a random 10-character uppercase password
3. **Jamf Integration**: Sends the new password to the device via Jamf's Set Recovery Lock command
4. **Local Storage**: Temporarily stores the password in a local SQLite database
5. **Verification**: Monitors Jamf Pro API until the new password is reflected in the system
6. **1Password Storage**: Once verified, moves the password from local database to 1Password
7. **Cleanup**: Removes the password from local storage, keeping only metadata

## Password Rotation

-   Passwords are automatically rotated every 30+ days
-   The exact rotation time includes a random offset to distribute load
-   Grace period handling ensures proper synchronisation between Jamf and the application
-   Devices that fail to update passwords are retried with exponential backoff

## Local Database Storage

The application uses an SQLite database (`state.db`) to track:

-   Device IDs and passwords during transition
-   Password creation timestamps
-   1Password vault item UUIDs
-   Grace period counters for sync issues
