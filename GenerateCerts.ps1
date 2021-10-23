<#
.SYNOPSIS
    This script 
    1. Generates a new Certificate Request from SharePoint
    2. Adjusts the certificate validation period on the Certificate Authority server
    3. Submits the request to the Certificate Authority server
    4. Approves the request on the Certificate Authority server
    5. Exports the Certificate to a .CER file
    6. Imports the Certficicate into SharePoint
    7. Cleans up temporary files

    Supports renewing certificates with the same FriendlyName
   
    The script must be executed with an Account that has permissions to issue certificates
    This means an account that is in the local "Administrators" group on the CA server
    
.PARAMETER FriendlyName|CertName (Mandatory)
    Name of the Certificate.
.PARAMETER CommonName|CertCommonName (Mandatory)
    Common Name in the Certificate.
#.PARAMETER ServerCertFileFolder|Share|SF (Mandatory)
#    FileShare on the Certificate Authority Server that is used to share the Certificate request and the .cer file (\\dc\labfiles\certs).
.PARAMETER caName
    [Optional] Name of the Certification Authority. If omitted, the default of the domain will be used")
.PARAMETER CertificateValiddays
    [Optional] Number of days the certificate is valid. If omitted, the default of the Certification Authority will be used
.PARAMETER AlternativeNames|SAN
    Comma separated list of Certificate Alternate names
.PARAMETER CertificateValiddays
    [Optional] Number of days the certificate is valid. If omitted, the default of the Certification Authority will be used
.PARAMETER CertStore
    [Optional] Certifcate store (Options: [EndEntity|Intermediate|Root|Pending]  Default:EndEntity 
.PARAMETER Password
    [Optional] Certficate Password
.PARAMETER Exportable
    Switch Certificate is Exportable ($true)
.PARAMETER Replace
    Switch Replace a certificate instead of importing a new certificate ($false)
.PARAMETER Renew
    Switch Creates a certificate request to renew an existing certificate instead of requesting a new certificate ($false)
.PARAMETER OrganizationalUnit|OU
    OU of the Certificate Issuer (Default: SharePoint Default Setting)
.PARAMETER Organization|Company
    Organization of the Certificate Issuer (Default: SharePoint Default Setting)
.PARAMETER Locality|City
    Locality of the Certificate Issuer (Default: SharePoint Default Setting)
.PARAMETER State|Province
    State of the Certificate Issuer (Default: SharePoint Default Setting)
.PARAMETER Country
    2-Letter Country of the Certificate Issuer (Default: SharePoint Default Setting)
.PARAMETER KeySize
    Certificate key size (0,2048,4096,8192,16384) (Default: SharePoint Default Setting)
.PARAMETER KeyAlgorithm
    Certificate KeyAlgorithm ("RSA","ECC")  (Default: SharePoint Default Setting)
.PARAMETER EllipticCurve
    Certificate EllipticCurve Algorithm("Default","nistP256","nistP384","nistP521") (Default: SharePoint Default Setting)
.PARAMETER HashAlgorithm
    Certificate Hash Algorithm ("Default","SHA256","SHA384","SHA512")  (Default: SharePoint Default Setting)
.PARAMETER Help
    Shows examples 
.Developed by Rainer Asbach
.LAST UPDATED
    2021-10-23 by RainerA
#>
Param(
    [Alias("CertName")]
    [Parameter(ParameterSetName="Run",Position=0,Mandatory=$true, HelpMessage="Name of the Certificate to be issued (ie. sni2")]
    [ValidateNotNullOrEmpty()]
    [string] $FriendlyName,
    
    [Alias ("CertCommonName")]
    [Parameter(ParameterSetName="Run",Position=1,Mandatory=$true, HelpMessage="Common Name of the Certificate to be issued (ie. sni2.contoso.com")]
    [ValidateNotNullOrEmpty()]
    [string] $CommonName,
    
    [Alias ("Share","SF")]  #left in for compatibitly with training doc, but no longer used
    [Parameter(ParameterSetName="Run",Position=2,Mandatory=$true, HelpMessage="FileShare on the Certificate Authority Server that is used to share the Certificate request and the .cer file (\\dc\labfiles\certs)")]
    [ValidateNotNullOrEmpty()]
    [string] $ServerCertFileFolder= "",
    
    [Alias("Overwrite","Clobber")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Overwrites existing Certificate Request files")]
    [switch] $force,

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="[Optional] Name of the Certification Authority. If omitted, the default of the domain will be used (contoso-dc-CA)")]
    [string] $caName,

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="[Optional] Number of days the certificate is valid. If omitted, the default of the Certification Authority will be used. (5) ")]
    [int] $CertificateValidDays,

    [Alias ("SAN")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Comma separated list of Certificate Alternate names (sp.contoso.com,sps.contoso.com,portal.contoso.com' ")]
    [string] $AlternativeNames ="",

    [Alias("PWD")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certificate Password ")]
    [string] $Password ="",

    [Alias("CertStore")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certifcate store (Options: [EndEntity|Intermediate|Root|Pending]  Default:EndEntity ")]
    [ValidateSet("EndEntity", "Intermediate", "Root" , "Pending")]   
    [string] $Store= "EndEntity",

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certificate is Exportable (`$true)")]
    [switch] $Exportable =$true ,

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Creates and processes a Certificate request to renew an existing certificate instead of adding a new certificate ")]
    [switch] $renew =$false,
        
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Replace an existing certificate instead of adding a new certificate ")]
    [switch] $replace =$false,
        
    [Alias("OU")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="OU of the Certificate Issuer (Default: SharePoint Default Setting) ")]
    [string] $OrganizationalUnit= "",

    [Alias("Org","Company")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Organization of the Certificate Issuer (Default: SharePoint Default Setting)  ")]
    [string] $Organization ="",

    [Alias("City")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Locality of the Certificate Issuer (Default: SharePoint Default Setting) ) ")]
    [string] $Locality= "",

    [Alias("Province")]
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="State of the Certificate Issuer (Default: SharePoint Default Setting) ")]
    [string] $State ="",

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Country of the Certificate Issuer (2-Letter Country Code)")]
    [string] $Country= "",
    
    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certificate key size ( [0|2048|4096|8192|16384] Default: 2048)")]
    [ValidateSet(0,2048,4096,8192,16384)]   
    [int] $KeySize= 0, 

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Encryption Key Algorithm ( [RSA|ECC] Default: RSA) ")]
    [ValidateSet("RSA","ECC")]
    [string] $KeyAlgorithm="",

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certificate Hash Algorithm ( [Default|SHA256|SHA384|SHA512] Default: SHA256) ")]
    [ValidateSet("Default","nistP256","nistP384","nistP521")]
    [string] $EllipticCurve="nistP256",

    [Parameter(ParameterSetName="Run",Mandatory=$false, HelpMessage="Certificate Hash Algorithm ( [Default|SHA256|SHA384|SHA512] Default: SHA256) ")]
    [ValidateSet("Default","SHA256","SHA384","SHA512")]
    [string] $HashAlgorithm="", 

    [Alias("?")]
    [Parameter(ParameterSetName="help",Mandatory=$false, HelpMessage="Shows this help")]
    [switch] $help
)

if ($help)
{
    Write-Host "This PowerShell script creates SharePoint Certificate request, uses the PowerShell module PSPKI to automatically issue Certificates
        and installs the certificates into the SharePoint Certificate Store"
    write-Host""
    


    return
}

function log{
Param(

    [string]$LogString , 
    [string]$color
)
    $d = get-date -Format "yyyy-MM-dd HH:mm:ss"
    if ([string]::IsNullOrEmpty($color))
    {
        write-host "$d : $LogString"
    }
    else
    {
        write-host "$d : $LogString" -ForegroundColor $color
    }
}

function IsCertificateInUse ($certName)
{
    $farm = Get-SPFarm 
    $cert = Get-SPCertificate -Identity $certName 
    
    if (($farm.CertificateManager.GetBoundWebApplicationsUrlZonePairs($cert)).count -gt 0) { return $true}
    if (($farm.CertificateManager.GetBoundWebApplicationsUsedInSmtpClient($cert)).count -gt 0) {return $true}  
    
    return $false
}

$OldCert = (Get-SPCertificate | ? {$_.Displayname -eq $FriendlyName})
if (!($OldCert) -and $renew)
{
    log "Certificate for renewal not found, pleagse do NOT use the option -renew" red
    return
} elseif ($OldCert -and !$renew)
{
    log "Certificate exists already, please use -renew option" red
    return
}

#region TestCAAccess
#Connect to CA
log "Connecting to CA $caname"

if (![string]::IsNullOrEmpty($caName))
{
    $ca  = Get-CertificationAuthority -Name $caName -Standalone
}
else 
{
    $ca  = Get-CertificationAuthority -Standalone
}
if ($ca -eq $null)
{
    throw ("Cannot connect to Certificate Authority $caName")
}
log $("Connected to CA " + $ca.DisplayName)

#Validate local administrators group membership on CA server
$CAcomputer = $ca.ComputerName
$user = $env:USERNAME
$group = "Administrators";
$groupObj =[ADSI]"WinNT://$CAcomputer/$group,group" 
$membersObj = @($groupObj.psbase.Invoke("Members")) 
$members = ($membersObj | foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})
If ($members -contains $user) {
    log "$user exists in the group $group on server $CAComputer" green
} Else {
    log "$user not exists in the group $group on server $caComputer" red
    throw ("This script only works when the user $user is member of the $group on the server $CAcomputer")
}
#endregion TestCAAccess


$certRequestFileName = Join-Path $env:temp "$FriendlyName.txt"
$cerFileName = Join-Path  $env:temp "$FriendlyName.cer"

#region PSPKI
log "Validating pspki PowerShell module"

# install / import pspki module 
if (( get-module -ListAvailable | ? {$_.name -match "pspki"}) -eq $null) 
{
    log "Installing module PSPKI" Yellow
    install-module pspki
}

log "importing pspki PowerShell module"

Import-Module pspki
#endregion #PSPKI

#region SPDefaultCertSettings
log "getting default cert Settings from SharePoint"

if (test-path $certRequestFileName) {remove-item $certRequestFileName -force}

$DefaultCertSettings= Get-SPCertificateSettings

log "Applying Default settings from SharePoint to Cert Request"

if ([string]::IsNullOrEmpty($OrganizationalUnit)) {$OrganizationalUnit = $DefaultCertSettings.DefaultOrganizationalUnit}
if ([string]::IsNullOrEmpty($Organization)) {$Organization = $DefaultCertSettings.DefaultOrganization}
if ([string]::IsNullOrEmpty($Locality)) {$Locality = $DefaultCertSettings.DefaultLocality}
if ([string]::IsNullOrEmpty($State)) {$State = $DefaultCertSettings.DefaultState}
if ([string]::IsNullOrEmpty($Country)) {$Country = $DefaultCertSettings.DefaultCountry}
if ([string]::IsNullOrEmpty($KeyAlgorithm)) {$KeyAlgorithm = $DefaultCertSettings.DefaultKeyAlgorithm}
if ($KeySize -eq 0) {$KeySize = $DefaultCertSettings.DefaultRsaKeySize}
if ([string]::IsNullOrEmpty($EllipticCurve)) {$EllipticCurve = $DefaultCertSettings.DefaultEllipticCurve}
if ([string]::IsNullOrEmpty($HashAlgorithm)) {$HashAlgorithm = $DefaultCertSettings.DefaultHashAlgorithm}
#endregion SPDefaultCertSettings

#region SearchExistingCert
if ($renew)
{
    log "Searching for certificate to renew"

    if ($OldCert.Count -gt 1)
    {
        throw ("Found multiple certificates")
    }
    if ($OldCert -eq $Null)
    {
        throw ("Cannot find a certificate for renwal. Please run Get-SPCertificate to get a list of existing certificates")
    }
    else
    {
        $OldCertID = $OldCert.ThumbPrint
        log "Found certificate $FriendlyName for renewal" green
    }

}
#endregion SearchExistingCert

#region PrepareCertRequest
log "Preparing Certificate Request on SP Server" 

if ($renew)
{
    log "Preparing Renew Request"
    ReNew-SPCertificate -Identity $OldCertID -FriendlyName $FriendlyName -Exportable -Path $certRequestFileName -Force
}
else
{

#region NewCertRequest
    [string[]]$CertAlternateNames = @();
    $certRequestTempfile=$env:temp + "\" + $FriendlyName + ".txt"
    if (![string]::IsNullOrEmpty($AlternativeNames))
    {
        if ($AlternativeNames.Contains(";") -or $AlternativeNames.Contains(","))
        {
            $CertAlternateNames = $AlternativeNames.replace(";",",").Split(',')
        }
        else 
        {
            $CertAlternateNames = $AlternativeNames
        }

        if ($KeyAlgorithm -eq "RSA")
        {

            New-SPCertificate -FriendlyName $FriendlyName  -CommonName $CommonName -OrganizationalUnit $OrganizationalUnit -Organization $Organization -Locality $Locality -State $State `
                -Country $Country -Exportable:$Exportable -KeySize $KeySize -HashAlgorithm $HashAlgorithm -Path $certRequestFileName -AlternativeNames $CertAlternateNames -Force
        }
        else 
        {
            New-SPCertificate -FriendlyName $FriendlyName  -CommonName $CommonName -OrganizationalUnit $OrganizationalUnit -Organization $Organization -Locality $Locality -State $State `
                -Country $Country -Exportable:$Exportable -EllipticCurve $EllipticCurve -HashAlgorithm $HashAlgorithm -Path $certRequestFileName  -AlternativeNames $CertAlternateNames -Force
        }

    } 
    else 
    {
        if ($KeyAlgorithm -eq "RSA")
        {
            #New-SPCertificate -FriendlyName $FriendlyName -CommonName $CommonName -Path $certRequestFileName

                New-SPCertificate -FriendlyName $FriendlyName  -CommonName $CommonName -OrganizationalUnit $OrganizationalUnit -Organization $Organization -Locality $Locality -State $State `
                    -Country $Country -Exportable:$Exportable -KeySize $KeySize -HashAlgorithm $HashAlgorithm -Path $certRequestFileName -Force
        }
        else 
        {
                New-SPCertificate -FriendlyName $FriendlyName  -CommonName $CommonName -OrganizationalUnit $OrganizationalUnit -Organization $Organization -Locality $Locality -State $State `
                  -Country $Country -Exportable:$Exportable -Path $certRequestFileName -EllipticCurve $EllipticCurve -HashAlgorithm $HashAlgorithm -Force:$force 
        }
    }
#endregion NewCertRequest
}
#endregion PrepareCertRequest


#region CertAuthority

#try 
#{
#region SubmitCert

    $OriginalCertValidationPeriod = (Get-CertificateValidityPeriod -CertificationAuthority $ca).ValidityPeriod
 
    if ($CertificateValidDays -gt 0)
    {
        $certValidationPeriod = $CertificateValidDays.ToString() +" Days"
        if ($OriginalCertValidationPeriod -ne $certValidationPeriod)
        {
            log "Changing Certification Validation time on Certification Authority to $CertificateValidDays Days"
            $cvp = $ca | Set-CertificateValidityPeriod -ValidityPeriod $certValidationPeriod  -RestartCA
            Start-Sleep 2
        }
    }
    log $("Submitting Certificate to Certificate Authority " + $ca.Displayname +" use default Expiration.")
    $certrequest = Submit-CertificateRequest -CertificationAuthority $ca -Path $CertRequestFileName 

#generate the certificate request when the input file exists
log "Submitting Certificate request"

if (!(test-path -path $certRequestFileName))
{
    throw "Certificate Request File $CertRequestFileName does not exist"
}
#endregion SubmitCert

#region ApproveCert
    #Approve the cert request / #issue the certificate
    log "Approving Certificate in Certificate Authority"
    if ($certrequest.Status -ne "UnderSubmission")
    {
        throw ("Certificate Submission request failed")
    }
    $certResult=  ($ca | Get-PendingRequest -RequestID $certrequest.RequestID | Approve-CertificateRequest)
#endregion ApproveCert

#region ExportCert
    #if the cert was issued, export it to a file
    if ($certResult.HResult -eq  0)
    {
        log "Exporting Certificate to $cerFileName"
        $r= Get-IssuedRequest -RequestID $certResult.InnerObject -CertificationAuthority $ca | Receive-Certificate | Export-Certificate -Type CERT -FilePath "$cerFileName" -Force
        log "Certificate was exported to $cerFileName" -color green
    } else {
        throw("Certificate could not be exported ")
    }
#endregion ExportCert

#} Catch {}
#Finally
#{
    Start-Sleep 2
    if ($OriginalCertValidationPeriod -ne (Get-CertificateValidityPeriod -CertificationAuthority $ca).ValidityPeriod)
    {
        log "Setting Certification Validation time on Certification Authority back to $OriginalCertValidationPeriod"
        $cvpOrg =   $ca | Set-CertificateValidityPeriod -ValidityPeriod $OriginalCertValidationPeriod -RestartCA
    }
#}
#endregion CertAuthority

#region ImportCert
#import certificate into SharePoint certificate store or replace an existing certificate
if (Test-Path -LiteralPath $cerFileName)
{
    $importedCert = $Null
    if (($replace -or $renew) -and (IsCertificateInUse($OldCertID)))
    {
        log "Replacing Cert in the SharePoint Cert Store $store"
        if (![String]::IsNullOrEmpty($Password))
        {
            #convert the Password into a secure String
            $SecPWD = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $importedCert=Import-SPCertificate $cerFileName -Replace -Store $Store -Password $SecPWD -Exportable
            log "Certificate $FriendlyName was replaced in SharePoint Cert store $Store"  Green 
        }
        else
        {
            $importedCert=Import-SPCertificate $cerFileName -Replace -Store $Store -Exportable
            log "Certificate $FriendlyName was replaced in SharePoint Cert store $Store"  Green 
        }
    } 
    else
    {
        log "Import Certificate in SharePoint Cert Store $store"
        if (![String]::IsNullOrEmpty($Password))
        {
            #convert the Password into a secure String
            $SecPWD = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $importedCert=Import-SPCertificate $cerFileName -Store $Store -Password $SecPWD -Exportable
            log "Certificate $FriendlyName was imported into SharePoint Cert store $store" green
        }
        else
        {
            $importedCert=Import-SPCertificate $cerFileName -Store $Store #-Exportable
            log "Certificate $FriendlyName was imported into SharePoint Cert store $store" green
        }
    }

    if ($importedCert -eq $null) 
    {
        write-host "Error importing or replacing Cert $FriendlyName in SharePoint Cert Store $store" red
    }

    if ($renew)
    {
        if (IsCertificateInUse($OldCertID))
        {
            log "Switching Certificates"
            Switch-SPCertificate -Identity $OldCertID -NewCertificate $importedCert
        }

        log "Removing Old Certificate"
        Remove-SPCertificate -Identity $OldCertID
    }

    #clean up
    remove-item $CertRequestFileName 
    #remove-item "\\$Serverpath\$FriendlyName.txt"
    remove-item $cerFileName

    log $($importedCert.FriendlyName + " is valid until " + $importedCert.NotAfter.DateTime)
}
else 
{
    log "The Certificate file $cerfilename was not created. Nothing to import" red
} 
#endregion ImportCert