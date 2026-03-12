# CML Lab Auto-Startup Setup

This section covers how to set up and use the CML (Cisco Modeling Labs) lab auto-startup scripts.

## Overview

The lab startup scripts automate the process of:
1. **Authenticating** with your CML instance using API credentials
2. **Starting** the lab topology automatically when needed
3. **Providing feedback** during startup

This lets workshop attendees click a single desktop shortcut to start the lab, then immediately click another shortcut to run validations.

## Configuration

### 1. Update CML Connection Details

Edit `config/cml_config.yaml` and set your CML instance details:

```yaml
cml:
  url: "https://your-cml-instance.com"
  username: "Administrator"
  password: "your_password"
  lab_id: "your-lab-id-uuid"
```

**Where to find these:**
- **url**: Your CML instance URL (e.g., `https://cml.demo.dcloud.cisco.com`)
- **username**: CML admin username
- **password**: CML admin password
- **lab_id**: UUID of your lab (visible in CML UI or API calls)

### 2. Test from PowerShell

Test the scripts manually first:

```powershell
# From the project root directory
.\start_lab.ps1
```

You should see:
```
Authenticating with CML...
✓ Authentication successful
Starting lab {lab_id}...
✓ Lab started successfully

Lab is starting up. Devices will be available shortly.
```

### 3. Create Desktop Shortcut

Create a desktop shortcut to `start_lab_hidden.vbs`:

**Windows Desktop Shortcut Setup:**
1. Right-click on desktop → **New** → **Shortcut**
2. Location: `C:\path\to\project\start_lab_hidden.vbs`
3. Name: `Start Lab`
4. Right-click shortcut → **Properties** → **Shortcut** tab
   - **Start in**: `C:\path\to\project\`
   - **Run**: `Minimized`
5. Click **OK**

**Optional: Add Custom Icon**
1. Right-click shortcut → **Properties** → **Shortcut** tab
2. Click **Change Icon**
3. Choose a suitable icon (or use `%SystemRoot%\System32\imageres.dll`)

## Usage Workflow

For workshop attendees:

1. **Click "Start Lab" shortcut** → Lab begins starting (silent, 1-2 minutes to fully boot)
2. **Wait for devices to be ready** → You'll know when devices respond to SSH
3. **Click "Run Validator" shortcut** → Validation runs and shows results
4. **Review validation results** → HTML report opens in Chrome

## Customization

### Multiple Labs

If you have multiple lab topologies:

1. Create additional config sections:
   ```yaml
   cml:
     url: "https://cml.demo.dcloud.cisco.com"

   lab1:
     username: "Administrator"
     password: "C1sco12345!"
     lab_id: "first-lab-uuid"

   lab2:
     username: "Administrator"
     password: "C1sco12345!"
     lab_id: "second-lab-uuid"
   ```

2. Create separate `start_lab_1.ps1` and `start_lab_2.ps1` wrappers for each lab

### Different Credentials

If your labs use different credentials, you can pass them as parameters:

```powershell
.\start_cml_lab.ps1 -CMLUrl "https://cml.instance.com" `
                    -Username "admin" `
                    -Password "password" `
                    -LabId "lab-uuid"
```

## Troubleshooting

### SSL Certificate Errors
If you get SSL certificate validation errors, the scripts automatically disable certificate validation for demo environments. If this still fails, ensure your CML instance has valid certificates.

### Authentication Fails
- Verify credentials in `config/cml_config.yaml`
- Check CML instance is accessible from your workstation
- Ensure the CML admin user exists and is active

### Lab Doesn't Start
- Verify the `lab_id` is correct
- Check that the lab exists in CML
- Ensure the lab isn't already running or in another state

### Can't Run PowerShell Scripts
If you get execution policy errors:
1. Run PowerShell as Administrator
2. Execute: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`
3. Confirm with `Y` and Enter

### Testing from Command Line

For debugging, run with visible output:

```powershell
# Run with output visible
powershell -NoProfile -ExecutionPolicy Bypass -File start_lab.ps1

# Or directly call the main script
powershell -NoProfile -ExecutionPolicy Bypass -File start_cml_lab.ps1 `
  -CMLUrl "https://cml.demo.dcloud.cisco.com" `
  -Username "Administrator" `
  -Password "C1sco12345!" `
  -LabId "your-lab-id"
```

## Integration with Validator

The lab startup and network validator are separate tools but work together:

1. **Lab Startup** (`start_lab.ps1`) - Boots up the network topology
2. **Validator** (`run_validator.ps1`) - Tests network configuration

Create a workshop workflow by having both shortcuts on the desktop, ready for attendees to use in sequence.

## Security Notes

⚠️ **Important**: This setup stores credentials in a configuration file:

- **Never commit** `config/cml_config.yaml` to a public repository if it contains real credentials
- **Add to .gitignore** if using in a shared repository
- **Use temporary accounts** for workshop labs (can be reset after each session)
- **Restrict file permissions** if sharing the lab environment with others

For production use, consider using environment variables or a secrets management system instead of storing credentials in files.

## API Reference

The scripts use the CML REST API:

- **Authenticate**: `POST /api/v0/authenticate`
  - Body: `{"username": "...", "password": "..."}`
  - Returns: JWT Bearer token

- **Start Lab**: `PUT /api/v0/labs/{lab_id}/start`
  - Headers: `Authorization: Bearer {token}`
  - Returns: Lab status

For more details, consult your CML instance's Swagger UI at `https://your-cml-instance/api/ui/`
