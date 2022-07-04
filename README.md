# Microsoft Defender for Identity Action Account Setup

This script configures a Microsoft Defender for Identity action account to perform response activities required from Microsoft Defender for Identity. The script performs the following tasks:
 
1. Creates a KDS Root Key if none exists. A KDS Root Key is needed when using Group Managed Service Accounts. For a test environment, use -10 for the effective time parameter.
2. It creates an Active Directory group for the Group Managed Service Account. The group is used to set permissions within Active Directory.
3. The script creates a group and adds the Domain Controllers to the group, which are allowed to retrieve the password for the Group Managed Service Account.
4. It created a Group Managed Service Account with the required parameters.
5. The scripts set the permissions within Active Directory on a given organization unit for the Group Managed Service Account to the required response actions within Microsoft Defender for Identity.

# Usage Microsoft Defender for Identity Action Account Setup

Import-Module Microsoft-Defender-for-Identity-Action-Account-Setup.psm1

CreateKdsRootKey -EffectiveTime 10

CreateADGroupGmsa -NameADGroup "MDIActionAccounts" -PathADGroup "OU=Groups,DC=thalpius,DC=local"

CreateADGroupPrincipalsManagedPassword -NameADGroup "MDISensors" -PathADGroup "OU=Groups,DC=thalpius,DC=local"

AddDomainControllersToADGroup -NameADGroup "MDISensors"

CreateGmsaAccount -NameGmsaAccount "MDIAction" -DescriptionGmsaAccount "MDI Action Account" -KerberosEncryptionType "AES256" -PrincipalGroup "MDISensors"

AddGmsaToADGroup -NameGmsaAccount "MDIAction" -NameADGroup "MDIActionAccounts"

AddPermissionsToOU -NameADGroup "MDIActionAccounts" -OrganizationUnit "OU=Groups,DC=thalpius,DC=local"

# Screenshot
