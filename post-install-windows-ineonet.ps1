<# 
Auteur : Bruno Melo
E-mail : iturri@tutanota.com
Date: 11/05/2023
Source : https://github.com/iturr1/Post-install-Windows-10-ineonet.git

.SYNOPSIS
Post-installation Windows 10.

.DESCRIPTION
Sript post-installation Windows 10 :
-> installation des programmes utiles et désintallation des programmes inutiles 
-> activation / désactivation fonctionaliées Windows
-> configuration d'énergie
-> désactivation d'UAC (User Access Control)
-> désactivation Actualitées Windows
-> creation d'un administrateur local

##################################################
Instrution d'exécution du script :
##################################################

1) 
Exécutez le script avec privilèges d'administrateur

2)
Si vous avez l'erreur "l’exécution de scripts est désactivée sur ce système", ouvrez Powershell en tant qu'administrateur 
et executez  la commande : 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned'.

#>   

<################################################################################################################
Tester si l'utilisateur a droits d'administrateur
################################################################################################################>

param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

<################################################################################################################
Installation / Désinstallation
################################################################################################################>

# Actualise la Microsoft Store apps
Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod

# Installer des programmes utils
winget install Microsoft.WindowsTerminal
winget install Microsoft.PowerShell
winget install Mozilla.Firefox
#winget install TheDocumentFoundation.LibreOffice
winget install VideoLAN.VLC
winget install 7zip.7zip
winget install Adobe.Acrobat.Reader.64-bit
winget install GIMP.GIMP

# Désinstaller des programmes inutiles
winget uninstall Disney.37853FC22B2CE_6rarf9sa4v8jt
winget uninstall Microsoft.BingNews_8wekyb3d8bbwe
winget uninstall Microsoft.BingWeather_8wekyb3d8bbwe
winget uninstall Microsoft.GamingApp_8wekyb3d8bbwe
winget uninstall Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe
winget uninstall Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe
winget uninstall Microsoft.OneDriveSync_8wekyb3d8bbwe
winget uninstall Microsoft.People_8wekyb3d8bbwe
winget uninstall "WildTangent wildgames Master Uninstall"
winget uninstall Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe
winget uninstall Microsoft.Xbox.TCUI_8wekyb3d8bbwe
winget uninstall Microsoft.XboxGameOverlay_8wekyb3d8bbwe
winget uninstall Microsoft.XboxGamingOverlay_8wekyb3d8bbwe
winget uninstall Microsoft.XboxIdentityProvider_8wekyb3d8bbwe
winget uninstall Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe
winget uninstall Microsoft.ZuneMusic_8wekyb3d8bbwe
winget uninstall Microsoft.ZuneVideo_8wekyb3d8bbwe
winget uninstall Microsoft.OneDrive
winget uninstall SpotifyAB.SpotifyMusic_zpdnekdrzrea0
# Uninstall Cortana
winget uninstall Microsoft.549981C3F5F10_8wekyb3d8bbwe

################################################################################################################

#installer des programmes qui sont pas sur msstore
Start-BitsTransfer -Source https://github.com/balena-io/etcher/releases/download/v1.18.4/balenaEtcher-Setup-1.18.4.exe -Destination C:\Windows\Temp
Start-Process -FilePath "C:\Windows\Temp\balenaEtcher-Setup-1.18.4.exe" -Verb RunAs -Wait
Start-BitsTransfer -Source https://aka.ms/vs/16/release/VC_redist.x86.exe -Destination C:\Windows\Temp\
Start-Process -FilePath "C:\Windows\Temp\VC_redist.x86.exe" -Verb RunAs -Wait
Start-BitsTransfer -Source https://aka.ms/vs/16/release/VC_redist.x64.exe -Destination C:\Windows\Temp\ 
Start-Process -FilePath "C:\Windows\Temp\VC_redist.x64.exe" -Verb RunAs -Wait
Start-BitsTransfer -Source https://eu.ninjarmm.com/agent/installer/6a9b20b6-8220-4461-b67e-b18380d9bb5c/1nouvelassetbureauprincipala1d4b1-5.3.6261-windows-installer.msi `
    -Destination C:\Windows\Temp
Start-Process msiexe.exe -Wait -ArgumentList '/I C:\Windows\Temp\1nouvelassetbureauprincipala1d4b1-5.3.6261-windows-installer.msi /quiet' -Verb RunAs -Wait
Start-BitsTransfer -Source https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16327-20214.exe -Destination C:\Windows\Temp
Start-Process -FilePath "C:\Windows\Temp\officedeploymenttool_16327-20214.exe" -Verb RunAs -Wait

<################################################################################################################
Afficher les extensions des fichiers, source :
http://superuser.com/questions/666891/script-to-set-hide-file-extensions
################################################################################################################>

Push-Location
Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
Set-ItemProperty . HideFileExt "0"
Pop-Location
Stop-Process -processName: Explorer -force # Redémarrer le service Explorer 

<################################################################################################################
Activer / Désactiver fonctionaliées Windows
################################################################################################################>

 #Activer SMB/CIFS
 
Do {
    $activateSMB1 = Read-Host "Veuillez-vous activer le protocol SMB1 ? [o/n]"
    if (($activateSMB1 -ine "O") -or ($activateSMB1 -ine "n")) {
        Write-Host "Choisissez O pour Oui ou N pour Non"
    }
} while (($activateSMB1 -ine "o") -or ($activateSMB1 -ine "n"))

if ($activateSMB1 -ieq "o") {

    Enable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart
    Enable-WindowsOptionalFeature -FeatureName SMB1Protocol-Client -Online -NoRestart
    Enable-WindowsOptionalFeature -FeatureName SMB1Protocol-Server -Online -NoRestart
    Enable-WindowsOptionalFeature -FeatureName SmbDirect -Online -NoRestart
} elseif ($activateSMB1 -ieq "n") {
    break
}

#Activation Framework .NET
Enable-WindowsOptionalFeature -FeatureName IIS-ASP -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName IIS-ASPNET -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName IIS-ASPNET45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName IIS-NetFxExtensibility -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName IIS-NetFxExtensibility45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName NetFx4-AdvSrvs -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName NetFx4Extended-ASPNET45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WAS-NetFxEnvironment -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-HTTP-Activation -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-HTTP-Activation45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-MSMQ-Activation45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-Pipe-Activation45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName NetFx4Extended-ASPNET45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WAS-NetFxEnvironment -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-TCP-Activation45 -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WCF-TCP-PortSharing45 -Online -All -NoRestart

#Désactiver Internet Explorer
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart

<################################################################################################################
Configuration d'energie
Options :
0 -> Ne rien faire : Aucune action n’est effectuée lorsque le couvercle du système est fermé.
1 -> Veille : Le système entre en veille lorsque le couvercle du système est fermé.
2 -> Mise en veille prolongée : Le système entre en veille prolongée lorsque le couvercle du système est fermé.
3 -> Eteindre : Le système s’arrête lorsque le couvercle du système est fermé.
################################################################################################################>

function Get-EnergyConfigOption {
    Write-Host "Option :
    `n0 -> Ne rien faire : Aucune action n’est effectuée lorsque le couvercle du système est fermé.
    `n1 -> Veille : Le système entre en veille lorsque le couvercle du système est fermé.
    `n2 -> Mise en veille prolongée : Le système entre en veille prolongée lorsque le couvercle du système est fermé.
    `n3 -> Eteindre : Le système s’arrête lorsque le couvercle du système est fermé."
}

function Set-MenuPlanOptions 
{
    param
    ($buttonLidPowerScheme, $batteryMains, $energyScheme, $buttonLidAction, $currentFunction)
    switch ($buttonLidPowerScheme) {
        0 {invoke-expression "powercfg.exe /SET$($batteryMains)VALUEINDEX SCHEME_$energyScheme SUB_BUTTONS $($buttonLidAction)ACTION 000"} 
        1 {invoke-expression "powercfg.exe /SET$($batteryMains)VALUEINDEX SCHEME_$energyScheme SUB_BUTTONS $($buttonLidAction)ACTION 001"}
        2 {invoke-expression "powercfg.exe /SET$($batteryMains)VALUEINDEX SCHEME_$energyScheme SUB_BUTTONS $($buttonLidAction)ACTION 002"}
        3 {invoke-expression "powercfg.exe /SET$($batteryMains)VALUEINDEX SCHEME_$energyScheme SUB_BUTTONS $($buttonLidAction)ACTION 003"}
        Default {
            Write-Host "`nL'option n'existe pas"
            Start-Sleep -Seconds 0.5
            $(& $currentFunction)

        }
    } 
}


function Set-ButtonPowerSaverPlan {
    Get-EnergyConfigOption
    $buttonDcMin = Read-Host -Prompt "`nChoisissez l'action en appuyant le bouton d'alimentation"
    Set-MenuPlanOptions  -buttonLidPowerScheme $buttonDcMin -batteryMains "DC" -energyScheme "MIN" `
    -buttonLidAction "PBUTTON" -currentFunction {Set-ButtonPowerSaverPlan}    
}

function Set-SectorLidPowerSaverPlan {
    Get-EnergyConfigOption
    $LidAcMin = Read-Host -Prompt "`nChoisissez l'action en fermant le capot sur secteur"
    Set-MenuPlanOptions  -buttonLidPowerScheme $LidAcMin -batteryMains "AC" -energyScheme "MIN" `
    -buttonLidAction "LID" -currentFunction {Set-SectorLidPowerSaverPlan}
}      

function Set-BatteryLidPowerSaverPlan {
    Get-EnergyConfigOption
    $LidDcMin = Read-Host -Prompt "`nChoisissez l'action en fermant le capot sur batterie"
    Set-MenuPlanOptions  -buttonLidPowerScheme $lidDcMin -batteryMains "DC" -energieScheme "MIN" `
    -buttonLidAction "LID" -currentFunction {Set-BatteryLidPowerSaverPlan}
}  

function Set-PowerSaverPlan {
    Write-Host 
    "`nConfiguration d'energie `n `nPlan d'alimentation économizeur d'énergie"
    Set-ButtonPowerSaverPlan
    Set-SectorLidPowerSaverPlan
    Set-BatteryLidPowerSaverPlan
}

################################################################################################################


function Set-ButtonHighPerformancePlan {
    Get-EnergyConfigOption
    $buttonDcHigh = Read-Host -Prompt "`nChoisissez l'action en appuyant le bouton d'alimentation"   
    Set-MenuPlanOptions  -buttonLidPowerScheme $buttonDcHigh -batteryMains "DC" -energieScheme "MAX" `
    -buttonLidAction "PBUTTON" -currentFunction {Set-ButtonHighPerformancePlan}
}

function Set-SectorLidHighPerformancePlan {
    Get-EnergyConfigOption
    $lidAcHigh = Read-Host -Prompt "`nChoisissez l'action en fermant le capot sur secteur"
    Set-MenuPlanOptions  -buttonLidPowerScheme $lidAcHigh -batteryMains "AC" -energieScheme "MAX" `
    -buttonLidAction "LID" -currentFunction {Set-SectorLidHighPerformancePlan}
}      

function Set-BatteryLidHighPerformancePlan {
    Get-EnergyConfigOption
    $lidDcHigh = Read-Host -Prompt "`nChoisissez l'action en fermant le capot sur batterie"
    Set-MenuPlanOptions  -buttonLidPowerScheme $lidDcHigh -batteryMains "DC" -energieScheme "MAX" `
    -buttonLidAction "LID" -currentFunction {Set-BatteryLidHighPerformancePlan}
}   


function Set-HighPerformancePlan {
    Write-Host 
    "`nConfiguration d'energie `n `nPlan d'alimentation hautes performances"
    Set-ButtonHighPerformancePlan
    Set-SectorLidHighPerformancePlan
    Set-BatteryLidHighPerformancePlan
}
################################################################################################################

function Set-ButtonBalancedPlan {
    Get-EnergyConfigOption
    $buttonDcBalanced = Read-Host -Prompt "Choisissez l'action en appuyant le bouton d'alimentation"
    Set-MenuPlanOptions  -buttonLidPowerScheme $buttonDcBalanced -batteryMains "DC" -energieScheme "BALANCED" `
    -buttonLidAction "PBUTTON" -currentFunction {Set-ButtonBalancedPlan}}

function Set-SectorLidBalancedPlan {
    Get-EnergyConfigOption
    $lidAcBalanced = Read-Host -Prompt "Choisissez l'action en fermant le capot sur secteur"
    Set-MenuPlanOptions  -buttonLidPowerScheme $lidAcBalanced -batteryMains "DC" -energieScheme "BALANCED" `
    -buttonLidAction "LID" -currentFunction {Set-SectorLidBalancedPlan}
}      

function Set-BatteryLidBalancedPlan {
    Get-EnergyConfigOption
    $lidDcBalanced = Read-Host -Prompt "Choisissez l'action en fermant le capot sur batterie"
    Set-MenuPlanOptions  -buttonLidPowerScheme $lidDcBalanced -batteryMains "DC" -energieScheme "BALANCED" `
    -buttonLidAction "LID" -currentFunction {Set-BatteryLidBalancedPlan}
}   

function Set-BalancedPlan {
    Write-Host 
    "`nConfiguration d'energie `n`nPlan d'alimentation équilibré"
    Set-ButtonBalancedPlan
    Set-SectorLidBalancedPlan
    Set-BatteryLidBalancedPlan
}


Set-PowerSaverPlan
Set-HighPerformancePlan
Set-BalancedPlan

<################################################################################################################
Configuration des registres
################################################################################################################>

#Désactiver UAC -> User Access Control

Do {
    $deactivateUAC = Read-Host "Veuillez-vous activer l'UAC -> User Access Control' ? [o/n]"
    if (($deactivateUAC -ine "O") -or ($deactivateUAC -ine "n")) {
        Write-Host "Choisissez O pour Oui ou N pour Non"
    }
} while (($deactivateUAC -ine "o") -or ($deactivateUAC -ine "n"))

if ($deactivateUAC -ieq "o") {

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "EnableLUA" -Value 0 -Force

} elseif ($activateSMB1 -ieq "n") {
    break
}


#Désactivation Actualitées Windows
Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -force

<################################################################################################################
Creation d'un administrateur local
################################################################################################################>
$nom= Read-Host "Merci de rentrer le NOM d'utilisateur à créer"
$prenom= Read-Host "Merci de rentrer le Prénom d'utilisateur à créer" 
$username= Read-Host "Merci de rentrer l'username d'utilisateur à créer"



   
    Do {
        $mdp= Read-Host "Merci de rentrer le mot de passe d'utilisateur à créer" -MaskInput
        $mdpConfirm= Read-Host "Merci de confirmer le mot de passe" -MaskInput
        if ($mdp -cne $mdpConfirm){
            Write-Host "Les mots de passe insérés sont différents"
        }
    } while ($mdp -cne $mdpConfirm)



New-LocalUser -Name $username -FullName  "$prenom $nom"   -Password (ConvertTo-SecureString -AsPlainText $mdp -Force) `
-PasswordNeverExpires   -Description "Local Admin"

Add-LocalGroupMember -Group "Administrateurs" -Member "$username"


<################################################################################################################
Redéfinition de la politique d'exécution 
################################################################################################################>
Set-ExecutionPolicy -ExecutionPolicy Undefined

<################################################################################################################
Redémarrer la machine
################################################################################################################>

Write-Host "L'ordinateur va redémarrer en ... `n"

5..1 | ForEach-Object {"$_"; Start-Sleep -Seconds 1} 

Restart-Computer

