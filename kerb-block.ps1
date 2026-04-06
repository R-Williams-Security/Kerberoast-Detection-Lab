# kerb-block.ps1
# Wazuh Active Response script — receives alert via stdin, disables the targeted AD account

$logPath = "C:\Security\SOAR.log"

try {
    # Wazuh passes the alert JSON to the script via standard input (stdin)
    $inputData = $null
    $inputData = [Console]::In.ReadToEnd()

    if ([string]::IsNullOrWhiteSpace($inputData)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: No input received from Wazuh" |
            Out-File -FilePath $logPath -Append
        exit 1
    }

    # Parse the JSON alert
    $alert = $inputData | ConvertFrom-Json

    # Extract the username from the Kerberos ticket event
    $targetUser = $alert.parameters.alert.data.win.eventdata.TargetUserName

    if ([string]::IsNullOrWhiteSpace($targetUser)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Could not extract TargetUserName from alert" |
            Out-File -FilePath $logPath -Append
        exit 1
    }

    # Skip built-in accounts to avoid locking out the domain
    $builtinAccounts = @('Administrator','krbtgt','ANONYMOUS LOGON')
    if ($builtinAccounts -contains $targetUser) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED built-in account: $targetUser" |
            Out-File -FilePath $logPath -Append
        exit 0
    }

    # Disable the account
    Import-Module ActiveDirectory
    Disable-ADAccount -Identity $targetUser -ErrorAction Stop

    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SUCCESS: Disabled account: $targetUser" |
        Out-File -FilePath $logPath -Append
}
catch {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $($_.Exception.Message)" |
        Out-File -FilePath $logPath -Append
    exit 1
}
