<#
 
.SYNOPSIS
  This script configures a Microsoft Defender for Identity action accounts.
 
.DESCRIPTION
 
  This script configures a Microsoft Defender for Identity action accounts by creating a Kds Root Key if needed,
  creates a Group Managed Service Account (gMSA) and set delegation on an Organization Unit for the gMSA account
  to perform actions needed from Microsoft Defender for Identity.

  Note: Run this script as a Domain Admin on the Domain Controller to be sure all dependencies are there to run
  the script succesfully. The script runs on all Microsoft Defender for Identity supported Operating Systems.
 
.EXAMPLE

  CreateKdsRootKey -EffectiveTime 10
  CreateADGroupGmsa -NameADGroup "MDIActionAccounts" -PathADGroup "OU=Groups,DC=thalpius,DC=local"
  CreateADGroupPrincipalsManagedPassword -NameADGroup "MDISensors" -PathADGroup "OU=Groups,DC=thalpius,DC=local"
  AddDomainControllersToADGroup -NameADGroup "MDISensors"
  CreateGmsaAccount -NameGmsaAccount "MDIAction" -DescriptionGmsaAccount "MDI Action Account" -KerberosEncryptionType "AES256" -PrincipalGroup "MDISensors"
  AddGmsaToADGroup -NameGmsaAccount "MDIAction" -NameADGroup "MDIActionAccounts"
  AddPermissionsToOU -NameADGroup "MDIActionAccounts" -OrganizationUnit "OU=Groups,DC=thalpius,DC=local"
  
.INPUTS
 
  None
 
.OUTPUTS
 
  Output will be shown in the terminal/console.
 
.NOTES
 
  Version:        0.1
  Author:         R. Roethof
  Creation Date:  04/07/2022
  Website:        https://thalpius.com
  Purpose/Change: Initial script development

#>

#------------------------------------------[Initialisations]---------------------------------------
 
# Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#-------------------------------------------[Declarations]-----------------------------------------

# Variables that can be set


#--------------------------------------------[Functions]-------------------------------------------

function CreateKdsRootKey {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the effectiveTime")]
        [ValidateNotNullOrEmpty()]
        [string]$EffectiveTime
    )
    begin {
        Write-Host "Check if a Kds Root key exists ..." -ForegroundColor Green
    }
    process {
        try {
            if (-not (Get-KdsRootKey).Count) {
                Add-KdsRootKey -EffectiveTime ((get-date).addhours($EffectiveTime)) | Out-Null
                Write-Host "  Created a Kds Root Key ..." -ForegroundColor Yellow
            }
            else {
                Write-Host "  A Kds Root Key already exists so no need to create one" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done checking if a Kds Root Key exists..." -ForegroundColor Green
        }
    }
}

function CreateADGroupGmsa {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the group")]
        [string]$NameADGroup,
        [parameter(Mandatory = $true, HelpMessage = "Specify a path")]
        [string]$PathADGroup
    )
    begin {
        Write-Host "Check if an AD group with the name $NameADGroup exists ..." -ForegroundColor Green
    }
    process {
        try {
            if (!([bool](Get-ADGroup -Filter { Name -eq $NameADGroup }))) {
                New-ADGroup -GroupCategory Security -GroupScope DomainLocal -Name $NameADGroup -Path $PathADGroup -SamAccountName $NameADGroup
                Write-Host "  Created an AD group with the name: $NameADGroup" -ForegroundColor Yellow
            }
            else {
                Write-Host "  An AD Group with the name $NameADGroup already exists" -ForegroundColor Yellow
            }    
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done checking if an AD group with the name $NameADGroup exists..." -ForegroundColor Green
        }
    }
}

function CreateADGroupPrincipalsManagedPassword {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the group")]
        [string]$NameADGroup,
        [parameter(Mandatory = $true, HelpMessage = "Specify a path")]
        [string]$PathADGroup
    )
    begin {
        Write-Host "Check if an AD group with the name $NameADGroup exists ..." -ForegroundColor Green
    }
    process {
        try {
            if (!([bool](Get-ADGroup -Filter { Name -eq $NameADGroup }))) {
                New-ADGroup -GroupCategory Security -GroupScope DomainLocal -Name $NameADGroup -Path $PathADGroup -SamAccountName $NameADGroup
                Write-Host "  Created an AD group with the name: $NameADGroup" -ForegroundColor Yellow
            }
            else {
                Write-Host "  An AD Group with the name $NameADGroup already exists" -ForegroundColor Yellow
            }    
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done checking if an AD group with the name $NameADGroup exists..." -ForegroundColor Green
        }
    }
}

function AddDomainControllersToADGroup {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the group")]
        [string]$NameADGroup
    )
    begin {
        Write-Host "Check if Domain Controller is part of the group $NameADGroup..." -ForegroundColor Green
    }
    process {
        try {
            Add-ADGroupMember -Identity $NameADGroup -Members (Get-ADGroup "Domain Controllers")
            Write-Host "  Added the Domain Controllers to the group: $NameADGroup" -ForegroundColor Yellow
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done checking if Domain Controller is part of the group $NameADGroup..." -ForegroundColor Green
        }
    }
}

function CreateGmsaAccount {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the account")]
        [ValidateNotNullOrEmpty()]
        [string]$NameGmsaAccount,
        [parameter(Mandatory = $true, HelpMessage = "Specify a description")]
        [ValidateNotNullOrEmpty()]
        [string]$DescriptionGmsaAccount,
        [parameter(Mandatory = $true, HelpMessage = "Specify the Kerberos encryption type")]
        [ValidateNotNullOrEmpty()]
        [string]$KerberosEncryptionType,
        [parameter(Mandatory = $true, HelpMessage = "Specify the group which contains the domain controllers")]
        [ValidateNotNullOrEmpty()]
        [string]$PrincipalGroup
    )
    begin {
        Write-Host "Check if a gMSA account with the name $NameGmsaAccount account exists ..." -ForegroundColor Green
    }
    process {
        try {
            if (!([bool](Get-ADServiceAccount -Filter { Name -eq $NameGmsaAccount }))) {
                New-ADServiceAccount -Name $NameGmsaAccount -Description $DescriptionGmsaAccount -DNSHostName $NameGmsaAccount"."$env:USERDNSDOMAIN -KerberosEncryptionType $KerberosEncryptionType -PrincipalsAllowedToRetrieveManagedPassword $PrincipalGroup
                Write-Host "  Created a gMSA account with the name: $NameGmsaAccount" -ForegroundColor Yellow
            }
            else {
                Write-Host "  A Group Managed Service Account with the name $NameGmsaAccount already exists" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done with checking if a gMSA account with the name $NameGmsaAccount exists  ..." -ForegroundColor Green
        }
    }
}

function AddGmsaToADGroup {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the account")]
        [string]$NameGmsaAccount,
        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the group")]
        [string]$NameADGroup
    )
    begin {
        Write-Host "Check if the gMSA account $NameGmsaAccount needs to be added to the group $NameADGroup..." -ForegroundColor Green
    }
    process {
        try {
            Add-ADPrincipalGroupMembership -Identity $NameGmsaAccount"$" -MemberOf $NameADGroup
            Write-Host "  Added the gMSA account AD group with the name: $NameADGroup" -ForegroundColor Yellow
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done checking if the gMSA account $NameGmsaAccount needs to be added to the group $NameADGroup..." -ForegroundColor Green
        }
    }
}
function AddPermissionsToOU {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the group which includes the gMSA accounts")]
        [string]$NameADGroup,
        [parameter(Mandatory = $true, HelpMessage = "Specify the organization group to set permission to")]
        [string]$OrganizationUnit
    )
    begin {
        Write-Host "Adding permissions for $NameADGroup to $OrganizationUnit..." -ForegroundColor Green
    }
    process {
        try {
            $GroupDistinguishedName = $(Get-ADGroup $NameADGroup).DistinguishedName
            dsacls.exe "$($OrganizationUnit)" /I:S /G "$GroupDistinguishedName`:WP;pwdLastSet;user" "$GroupDistinguishedName`:CA;Reset Password;user" "$GroupDistinguishedName`:WP;userAccountControl;user" | Out-Null
            Write-Host "  Setting permissions for $NameADGroup to $OrganizationUnit" -ForegroundColor Yellow
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-Host "Done adding permissions for $NameADGroup to $OrganizationUnit..." -ForegroundColor Green
        }
    }
}