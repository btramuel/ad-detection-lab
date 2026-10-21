<#
    Provision-LabAD.ps1
    Populates the studentlab.local domain with a realistic OU / group / user structure.
    Run on the domain controller in an elevated PowerShell session.
    Idempotent — existing objects are skipped, so it's safe to re-run.

    Author: Brian Tramuel
#>

Import-Module ActiveDirectory

$DomainDN    = "DC=studentlab,DC=local"
$DefaultPass = ConvertTo-SecureString "P@ssw0rd-Lab-2026!" -AsPlainText -Force

function New-LabOU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
        Write-Host "  [ok]   OU $dn"
    } else { Write-Host "  [skip] OU $dn exists" }
    return $dn
}

function New-LabGroup {
    param([string]$Name, [string]$Path, [string]$Desc)
    if (-not (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $Path -Description $Desc
        Write-Host "  [ok]   group $Name"
    } else { Write-Host "  [skip] group $Name exists" }
}

function New-LabUser {
    param([string]$First, [string]$Last, [string]$Dept, [string]$Title, [string]$OUPath)
    $sam = ("{0}.{1}" -f $First.Substring(0,1), $Last).ToLower()
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "$First $Last" -GivenName $First -Surname $Last `
            -SamAccountName $sam -UserPrincipalName "$sam@studentlab.local" `
            -DisplayName "$First $Last" -Title $Title -Department $Dept `
            -Path $OUPath -AccountPassword $DefaultPass -Enabled $true -ChangePasswordAtLogon $false
        Write-Host "  [ok]   user $sam ($Title)"
    } else { Write-Host "  [skip] user $sam exists" }
    return $sam
}

Write-Host "`n=== OUs ==="
$Root = New-LabOU -Name "CorpLab" -Path $DomainDN
$Emp  = New-LabOU -Name "Employees" -Path $Root
$Grp  = New-LabOU -Name "Groups" -Path $Root
$null = New-LabOU -Name "Workstations" -Path $Root
$DeptOU = @{}
foreach ($d in "IT","Finance","HR","Sales") { $DeptOU[$d] = New-LabOU -Name $d -Path $Emp }

Write-Host "`n=== Groups ==="
New-LabGroup -Name "IT-Admins"     -Path $Grp -Desc "Domain IT administrators"
New-LabGroup -Name "Helpdesk"      -Path $Grp -Desc "Tier 1 support"
New-LabGroup -Name "Finance-Users" -Path $Grp -Desc "Finance department"
New-LabGroup -Name "HR-Users"      -Path $Grp -Desc "HR department"
New-LabGroup -Name "Sales-Users"   -Path $Grp -Desc "Sales department"

Write-Host "`n=== Users ==="
$Roster = @(
    @("Alice","Nguyen","IT","Systems Administrator"),
    @("Marcus","Reed","IT","Network Engineer"),
    @("David","Olsen","Finance","Financial Analyst"),
    @("James","Carter","HR","HR Generalist"),
    @("Rachel","Kim","Sales","Sales Manager")
)
foreach ($p in $Roster) {
    $first,$last,$dept,$title = $p
    $sam = New-LabUser -First $first -Last $last -Dept $dept -Title $title -OUPath $DeptOU[$dept]
    switch ($dept) {
        "IT"      { Add-ADGroupMember -Identity "IT-Admins"     -Members $sam -ErrorAction SilentlyContinue }
        "Finance" { Add-ADGroupMember -Identity "Finance-Users" -Members $sam -ErrorAction SilentlyContinue }
        "HR"      { Add-ADGroupMember -Identity "HR-Users"      -Members $sam -ErrorAction SilentlyContinue }
        "Sales"   { Add-ADGroupMember -Identity "Sales-Users"   -Members $sam -ErrorAction SilentlyContinue }
    }
}

Write-Host "`nDone. Verify: Get-ADUser -Filter * | ft Name,SamAccountName"
