# Microsoft Defender for Identity Action Account Setup

This script configures a Microsoft Defender for Identity action account to perform response activities required from Microsoft Defender for Identity. The script performs the following tasks:
 
Creates a KDS Root Key if none exists. A KDS Root Key is needed when using Group Managed Service Accounts. For a test environment, use -10 for the effective time parameter.
It creates an Active Directory group for the Group Managed Service Account. The group is used to set permissions within Active Directory.
The script creates a group and adds the Domain Controllers to the group, which are allowed to retrieve the password for the Group Managed Service Account.
It created a Group Managed Service Account with the required parameters.
The scripts set the permissions within Active Directory on a given organization unit for the Group Managed Service Account to the required response actions within Microsoft Defender for Identity.

