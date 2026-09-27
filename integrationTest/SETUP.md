# Setting up a target for integrationTest

## Non-Kerberos setup

Two ways to get a Windows host that satisfies `WINRM_IT_HOST` /
`WINRM_IT_USER` / `WINRM_IT_PASSWORD` (see README.md for the full env var
contract). Both run the exact same PowerShell below — only how it gets onto
the machine differs.

```powershell
netsh advfirewall firewall add rule name="WinRM-HTTP-In" dir=in action=allow protocol=TCP localport=5985

winrm quickconfig -q
winrm set winrm/config/service/Auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

Enable-WSManCredSSP -Role Server -Force
winrm set winrm/config/service/Auth '@{CredSSP="true"}'

$password = ConvertTo-SecureString "Str0ngP@ssw0rd!" -AsPlainText -Force
New-LocalUser -Name "winrmtest" -Password $password -PasswordNeverExpires -AccountNeverExpires -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Remote Management Users" -Member "winrmtest" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "winrmtest" -ErrorAction SilentlyContinue
```

Save it as `baseline-winrm.ps1` before either recipe below.

### Recipe 1: a local Windows 11 VM with UTM (macOS only, free, no cloud account needed)

UTM is macOS-only. On Linux or Windows, use whatever virtualization you
already have (VirtualBox, libvirt/QEMU, Hyper-V, VMware Workstation, ...),
set up a Windows guest, paste `baseline-winrm.ps1` into it, and skip to
step 6.

Works best on Apple Silicon: Windows Server has no ARM64 build and is
painfully slow emulated, but Windows 11 ARM64 runs natively under
virtualization and covers everything these four scenarios need — just a
WinRM listener and a local account, nothing Server-specific.

1. Install [UTM](https://mac.getutm.app/) (free, open source).
2. Use UTM's guided "Install Windows" flow for Apple Silicon — it downloads
   a Microsoft-signed ARM64 Windows 11 VHDX (Insider Preview build)
   directly, no separate ISO hunting.
3. Leave networking on UTM's default "Shared Network" mode — the guest gets
   its own IP the Mac can reach directly (typically `192.168.64.x`), no
   firewall/router traversal since it never leaves the machine.
4. Once Windows is installed and you're at a desktop, open PowerShell
   **as Administrator** and paste the contents of `baseline-winrm.ps1`
   directly (no need to save it as a file inside the guest — paste and run).
5. Find the guest's IP: `ipconfig` inside the VM, or UTM's own network
   inspector.
6. Copy `integrationTest/.env.example` to `integrationTest/.env.integration`
   and fill in:
   ```
   export WINRM_IT_HOST=<vm-ip>
   export WINRM_IT_USER=winrmtest
   export WINRM_IT_PASSWORD='Str0ngP@ssw0rd!'
   ```
   Then, from the Mac:
   ```sh
   set -a; source integrationTest/.env.integration; set +a
   go test ./integrationTest/... -run 'TestWinRMIntegration/(NoEncryption|NTLM|NTLMSealed|CredSSP)' -v
   ```

On an Intel Mac, the real Windows Server evaluation ISO (free, 180 days)
works just as well here under hardware-accelerated virtualization — same
script, same steps, just a different guest OS.

### Recipe 2: automated provisioning on GCP (no RDP needed)

GCP's Windows images run Google's own guest agent (`GCEWindowsAgent`), which
runs a script from instance metadata as SYSTEM on first boot, before any
external connection exists. Other cloud providers have their own equivalent
mechanism for this — GCP just uses its own agent instead of cloud-init or
similar. Either way, `baseline-winrm.ps1` runs unattended and the box is
ready to use with no RDP session needed.

Requires the `gcloud` CLI authenticated and a project selected — this isn't
free unless you're running it within GCP's free trial credit.

```sh
gcloud config set compute/region europe-west9   # or whichever region you prefer
gcloud config set compute/zone europe-west9-a

gcloud compute firewall-rules create winrm-lab \
  --allow=tcp:5985 \
  --source-ranges=<your-public-ip>/32

gcloud compute instances create winrm-test \
  --machine-type=e2-medium \
  --image-family=windows-2022 \
  --image-project=windows-cloud \
  --boot-disk-size=50GB \
  --metadata-from-file sysprep-specialize-script-ps1=baseline-winrm.ps1
```

Wait a couple of minutes for the specialize pass and first boot, then copy
`integrationTest/.env.example` to `integrationTest/.env.integration` and
fill in:

```
export WINRM_IT_HOST=$(gcloud compute instances describe winrm-test --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
export WINRM_IT_USER=winrmtest
export WINRM_IT_PASSWORD='Str0ngP@ssw0rd!'
```

then:

```sh
set -a; source integrationTest/.env.integration; set +a
go test ./integrationTest/... -run 'TestWinRMIntegration/(NoEncryption|NTLM|NTLMSealed|CredSSP)' -v
```

When done: `gcloud compute instances delete winrm-test`.

## Kerberos setup

`Kerberos` and `KerberosEncrypted` need a full Active Directory domain, not
just a WinRM-enabled host — this is a separate, second target from the
non-Kerberos one above, with its own script and its own env var group
(`WINRM_IT_KERBEROS_*`). This recipe provisions that domain controller on
GCP.

Promoting a box to a domain controller forces a reboot partway through the
setup, so a single-boot script like `baseline-winrm.ps1` isn't enough — this
needs a two-phase script that picks up where it left off after that reboot.
GCP's `windows-startup-script-ps1` metadata key runs on **every** boot
(unlike `sysprep-specialize-script-ps1`, which only runs once), so a marker
file turns it into a simple two-phase state machine:

```powershell
# ad-dc-bootstrap.ps1 — set as windows-startup-script-ps1 (NOT
# sysprep-specialize-script-ps1, which only runs once and won't survive the
# Install-ADDSForest reboot).

$marker = "C:\winrm-lab-state.txt"
$state = if (Test-Path $marker) { Get-Content $marker } else { "start" }

if ($state -eq "start") {
    # GCP's Windows images ship with a blank local Administrator password,
    # which fails Install-ADDSForest's prerequisite check below (and also
    # leaves you with no account to RDP in with). Set one explicitly.
    net user Administrator "Str0ngP@ssw0rd!"

    netsh advfirewall firewall add rule name="WinRM-HTTP-In" dir=in action=allow protocol=TCP localport=5985
    netsh advfirewall firewall add rule name="Kerberos-TCP-In" dir=in action=allow protocol=TCP localport=88
    netsh advfirewall firewall add rule name="Kerberos-UDP-In" dir=in action=allow protocol=UDP localport=88
    winrm quickconfig -q
    winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'  # needed for the unencrypted Kerberos subtest
    # On a Domain Controller, winrm quickconfig's default RootSDDL grants
    # access to Builtin Administrators only — it omits the Remote Management
    # Users (RM) ACE that a member server gets by default. Without it,
    # krbtest authenticates fine via Kerberos but every operation comes back
    # AccessDenied. Add the RM ACE explicitly. Use the WSMan provider, not
    # `winrm set` — its command-line parser mishandles the semicolons/parens
    # in an SDDL string even when quoted.
    Set-Item -Path WSMan:\localhost\Service\RootSDDL `
        -Value "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;RM)(A;;GR;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)" -Force

    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    $safeModePwd = ConvertTo-SecureString "Str0ngP@ssw0rd!" -AsPlainText -Force
    try {
        # Only advance the marker once promotion actually succeeds — if this
        # throws (e.g. a prerequisite check fails) we want the next boot to
        # retry Install-ADDSForest, not skip straight past it.
        Install-ADDSForest -DomainName "winrmtest.local" -DomainNetbiosName "WINRMTEST" `
            -SafeModeAdministratorPassword $safeModePwd -InstallDns -Force -NoRebootOnCompletion:$false `
            -ErrorAction Stop
        "promoted" | Set-Content $marker
        # Install-ADDSForest reboots on its own; this script re-runs automatically
        # on that next boot because windows-startup-script-ps1 fires every boot.
    } catch {
        Write-Output "Install-ADDSForest failed, will retry next boot: $_"
    }
}
elseif ($state -eq "promoted") {
    # Active Directory Web Services isn't up yet this early in boot on a
    # freshly promoted DC — the AD PowerShell module needs it. Wait for it
    # rather than fail the whole script (which would just retry next boot).
    $adws = Get-Service ADWS -ErrorAction SilentlyContinue
    $waited = 0
    while ((-not $adws -or $adws.Status -ne "Running") -and $waited -lt 300) {
        Start-Sleep -Seconds 10
        $waited += 10
        $adws = Get-Service ADWS -ErrorAction SilentlyContinue
    }

    Import-Module ActiveDirectory
    $password = ConvertTo-SecureString "Str0ngP@ssw0rd!" -AsPlainText -Force
    New-ADUser -Name "krbtest" -SamAccountName krbtest -UserPrincipalName krbtest@winrmtest.local `
        -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
    Add-ADGroupMember -Identity "Remote Management Users" -Members krbtest
    "done" | Set-Content $marker
}
```

Create the instance with this script as `windows-startup-script-ps1` (not
`sysprep-specialize-script-ps1` — see the comment above) and open the extra
Kerberos ports alongside WinRM:

```sh
gcloud compute instances create dc01 \
  --machine-type=e2-medium \
  --image-family=windows-2022 \
  --image-project=windows-cloud \
  --boot-disk-size=50GB \
  --metadata-from-file windows-startup-script-ps1=ad-dc-bootstrap.ps1

gcloud compute firewall-rules create winrm-lab-kerberos \
  --allow=tcp:5985,tcp:3389,tcp:88,udp:88 \
  --source-ranges=<your-public-ip>/32
```

Give it 5–10 minutes total (first boot, feature install, forest promotion,
automatic reboot, second boot, user creation) before treating it as ready.
`gcloud compute instances get-serial-port-output dc01` is useful for
watching progress without RDPing in.

If you do need to RDP in to debug, target `krbtest` rather than
`Administrator` — once `Install-ADDSForest` promotes the box, the built-in
`Administrator` account can no longer log in over RDP. Get `krbtest`'s
password with `gcloud compute reset-windows-password dc01 --user krbtest`.

Point the Mac at the instance (either its IP via an `/etc/hosts` entry for
`dc01.winrmtest.local`, or real DNS if you have it).

Save this as `krb5.conf` (point `WINRM_IT_KERBEROS_CONFIG` at this file):

```ini
[libdefaults]
    default_realm = WINRMTEST.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    WINRMTEST.LOCAL = {
        kdc = dc01.winrmtest.local
        admin_server = dc01.winrmtest.local
    }

[domain_realm]
    .winrmtest.local = WINRMTEST.LOCAL
    winrmtest.local = WINRMTEST.LOCAL
```

Now verify Kerberos works independent of Go — macOS ships Heimdal `kinit`.
Since this isn't the system's default `/etc/krb5.conf`, point `KRB5_CONFIG`
at it first:

```sh
export KRB5_CONFIG=$(pwd)/krb5.conf
kinit krbtest@WINRMTEST.LOCAL
klist
```

If Kerberos SPN lookup fails against the default machine-account SPN
mapping, register it explicitly:

```powershell
setspn -A HTTP/dc01.winrmtest.local dc01
```

Then fill in `integrationTest/.env.integration`:

```
export WINRM_IT_KERBEROS_HOST=dc01.winrmtest.local   # or the raw IP + /etc/hosts entry
export WINRM_IT_KERBEROS_REALM=WINRMTEST.LOCAL
export WINRM_IT_KERBEROS_USER=krbtest
export WINRM_IT_KERBEROS_PASSWORD='Str0ngP@ssw0rd!'
export WINRM_IT_KERBEROS_CONFIG=/path/to/krb5.conf
```

and run the scenario:

```sh
set -a; source integrationTest/.env.integration; set +a
go test ./integrationTest/... -run 'TestWinRMIntegration/Kerberos' -v
```

When done, `gcloud compute instances stop dc01` — stopping (rather than
deleting) avoids having to redo the AD setup next time; you're only billed
for the persistent disk while it's stopped, not the compute time.

The same two-phase approach works on other providers (OVHcloud, Azure, ...)
too, though their boot-time metadata mechanisms differ — see this repo's
README.md for the general picture of what runs at boot on which provider.
The script above specifically relies on GCP's `windows-startup-script-ps1`
semantics.
