$DOMAIN = "devilops.se"
# $IP = ""
[Array] $IPs=""
[Array] $SUBDOMAIN=""
$HTTP_CRL_SRV=""
$CA_OUT_DIR = (Get-Location).Path+"\Certificates\CA\"
$CERT_OUT_DIR = (Get-Location).Path+"\Certificates\EndEntity\"
$CRL_OUT_DIR = (Get-Location).Path+"\Certificates\CA\CRL"

Function New-OpenSSLCA() {
        param($CA_NAME)
    if ($DOMAIN -eq "") {
        $DOMAIN = Read-Host -Prompt "Enter domainname:"
    }
    # $CA_NAME = Read-Host -Prompt  "Enter a name for Certificate Authority: "
    $CA_FQDN = "$CA_NAME.$DOMAIN"
    $CA_OUT_KEY = "$CA_OUT_DIR'ca-'$CA_FQDN.key"
    $CA_OUT_CRT = "$CA_OUT_DIR'ca-'$CA_FQDN.crt"
    Invoke-Expression "openssl genrsa -out $CA_OUT_KEY 4096"
    Invoke-Expression "openssl req -x509 -new -nodes -sha512 -days 3650 -subj `/C=SE/ST=Milkyway/L=Galaxy/O=$DOMAIN`/OU=MGMT/CN=$CA_FQDN -key $CA_OUT_KEY -out $CA_OUT_CRT"
    # New-OpenSSLEndEntityCSR -CA_Name $CA_FQDN
    exit
    
}
Function New-OpenSSLEndEntityCSR(){
    param(
            $CA_NAME,
            $SUB_DOMAIN_NAME,
            $IPs
        ) 
    
    if ($SUB_DOMAIN_NAME -eq "" -or $null -eq $SUB_DOMAIN_NAME) {
        $SUB_DOMAIN_NAME = Read-Host -Prompt  "Enter hostname"
        $answer = Read-Host -Prompt "Add another hostname to certificate?(y/n)"
        if($answer -eq "y" -or $answer -eq "Y") {
            [Array] $SUBDOMAIN = $SUB_DOMAIN_NAME
            do {
                $SUB = Read-Host -Prompt  "Enter hostname('s + Enter' equals Abort)"
                if($SUB -ne "s") {
                    $SUBDOMAIN += $SUB
                }
                
            }
            while ($SUB -ne "s")
        } 
    }
    # TODO Fix a function for this
    if($IPs -eq "" -or $null -eq $IPs) {
        $answer = Read-Host -Prompt "Want to add IP to certificate?(y/n)"
        if ($answer -eq "y" -or $answer -eq "Y") {
            do {
                $IP = Read-Host -Prompt "Enter IP('s + Enter' equals Abort)"
                if($IP -ne "s") {
                    $IPs += $IP
                }
            }
            while($IP -ne "s") 
        }
    }
    if ($HTTP_CRL_SRV -eq "") {
        $HTTP_CRL_SRV = Read-Host -Prompt "Enter crl subdomain(default crl.$DOMAIN)"
        if($HTTP_CRL_SRV -eq "" -or $null -eq $HTTP_CRL_SRV) {
            $HTTP_FILE=$DOMAIN+".crl"
            $HTTP_CRL_SRV="crl."+$DOMAIN+"/$HTTP_FILE"
        } else {
            $HTTP_FILE=$DOMAIN+".crl"
            $HTTP_CRL_SRV+="/$HTTP_FILE"
        }

        
    }
    if($SUBDOMAIN.Length -gt 1){
        $KEYNAME = $SUBDOMAIN[0]+"."+$DOMAIN
        [Array] $LIST = "DNS.1="+$KEYNAME
        $x=2;
        foreach($sub in $SUBDOMAIN) {
            if($sub -ne "s") {
                $FQDN = $sub
                if($SUBDOMAIN.Length -gt 1) {
                    $LIST +="DNS.$x=$FQDN"
                } else {
                    $LIST +="DNS.$x=$FQDN"
                }
                $x++
                $FQDN=""
            }
        }
        
        $ALT_NAMES = "`n[alt_names]", $LIST
        $CLEANSUBDOMAIN = $SUBDOMAIN[0]
    } else {
        $FQDN = $SUB_DOMAIN_NAME+"."+$DOMAIN
        $LIST +="DNS.1=$FQDN"
        $ALT_NAMES = "`n[alt_names]", $LIST
        $KEYNAME = $SUB_DOMAIN_NAME+"."+$DOMAIN
        $CLEANSUBDOMAIN = $SUB_DOMAIN_NAME
    }
    $DATE = Get-Date -Format "yyyy-MM-dd"
    if (Test-Path -Path "$CERT_OUT_DIR\$CLEANSUBDOMAIN") {
        if (Test-Path -Path "$CERT_OUT_DIR\$CLEANSUBDOMAIN\$DATE") {
            $CERT_OUT_KEY = "$CERT_OUT_DIR$CLEANSUBDOMAIN\$DATE\$KEYNAME.key"
            $CERT_REQ_OUT = "$CERT_OUT_DIR$CLEANSUBDOMAIN\$DATE\$KEYNAME.csr"
            Invoke-Expression "openssl genrsa -out $CERT_OUT_KEY 4096"
            $subject="/C=SE/ST=Milkyway/L=Galaxy/O=$DOMAIN/OU=Server/CN=$KEYNAME"
            Invoke-Expression "openssl req -sha512 -new -subj $subject -key $CERT_OUT_KEY -out $CERT_REQ_OUT"
            # $SAN = "DNS.1=$FQDN,","DNS.2=$IP"
            $v3EXT = "authorityKeyIdentifier=keyid,issuer","basicConstraints=CA:FALSE","keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment","extendedKeyUsage=serverAuth","crlDistributionPoints=URI:http://$HTTP_CRL_SRV","subjectAltName=@alt_names"
            if($IPs -is [Array]){
                $x=1;
                foreach($myIP in $IPs) {
                    if($myIP -ne "s"){
                        if($IPs.Length -gt 1) {
                            $LIST_OF_IPs +="IP.$x=$myIP,"
                        } else {
                            $LIST_OF_IPs +="IP.$x=$myIP"
                        }
                        $x++
                    }
                }
                Write-Host $LIST_OF_IPs
                $ALT_NAMES += $LIST_OF_IPs
            } else {
                $LIST_OF_IPs +="IP.$x=$IPs"
                $ALT_NAMES += $LIST_OF_IPs
            }
            # if ($IP -ne "") {
            #     $ALT_NAMES += "IP.1=$IP"
            # }
            $v3EXT | Set-Content .\v3.ext 
            $ALT_NAMES | Add-Content .\v3.ext

            return $CERT_OUT_KEY, $CERT_REQ_OUT, ("$CERT_OUT_DIR$CLEANSUBDOMAIN\$DATE\$KEYNAME")
        } else {
            [void](New-Item -ItemType Directory -Path "$CERT_OUT_DIR\$CLEANSUBDOMAIN\$DATE")
                if(Test-Path -Path $CERT_OUT_DIR\$CLEANSUBDOMAIN\$DATE) {
                    New-OpenSSLEndEntityCSR -CA_NAME $CA_NAME -SUB_DOMAIN_NAME $SUBDOMAIN -IPs $IPs
                } else {
                    [void](New-Item -ItemType Directory -Path "$CERT_OUT_DIR\$CLEANSUBDOMAIN\$DATE") 
                    if(Test-Path -Path $CERT_OUT_DIR\$CLEANSUBDOMAIN) {
                        New-OpenSSLEndEntityCSR -CA_NAME $CA_NAME -SUB_DOMAIN_NAME $SUBDOMAIN -IPs $IPs
                    } else {
                        Write-Error -Message "Directory: $DATE not found under $CERT_OUT_DIR\$CLEANSUBDOMAIN"-Category ObjectNotFound 
                    }
                }
        }
        
    } else {
        [void](New-Item -ItemType Directory -Path "$CERT_OUT_DIR\$CLEANSUBDOMAIN") 
        if(Test-Path -Path $CERT_OUT_DIR\$CLEANSUBDOMAIN) {
            New-OpenSSLEndEntityCSR -CA_NAME $CA_NAME -SUB_DOMAIN_NAME $SUBDOMAIN -IPs $IPs
        }
    }
    
    # New-EndEntityCertificate -CAin $CA_Name -CSRin $FQDN
}
Function New-EndEntityCertificate() {
        param( $CA_IN, $CSR_IN)
        $CA_CRT = $CA_IN[0]
        $CA_KEY = $CA_IN[1]
        $CSR = $CSR_IN[0]
        $CERT_OUT_CRT = $CSR_IN[1]+".crt"
        Invoke-Expression "openssl x509 -req -sha512 -days 3650 -extfile v3.ext -CA $CA_CRT -CAkey $CA_KEY -CAcreateserial -in $CSR -out $CERT_OUT_CRT"
}

$CA_ANSWER = Read-Host -Prompt "Create CA?"

if ($CA_ANSWER -eq "y" -or $CA_ANSWER -eq "Y") {
    $CA_NAME = Read-Host -Prompt  "Enter a name for Certificate Authority"
    $PATHS = New-OpenSSLCA -CA_NAME $CA_NAME
    Write-Output "00" | Set-Content "$CA_OUT_DIR\crlnumber"

} else {
    $ENDENTITY_ANSWER = Read-Host -Prompt "Create Certificate?"
    if ($ENDENTITY_ANSWER -eq "y" -or $ENDENTITY_ANSWER -eq "Y") {
        $PATHS = (Get-ChildItem -Path $CA_OUT_DIR -File ).FullName
        $CERT_PATHS = New-OpenSSLEndEntityCSR
        New-EndEntityCertificate -CA_IN $PATHS[0],$PATHS[1] -CSR_IN $CERT_PATHS[1], $CERT_PATHS[2]

        $P12_OUT = Read-Host -Prompt "Want to create p12 package?"

        if($P12_OUT -eq "y" -or $P12_OUT -eq "Y") {
            $KEY = $CERT_PATHS[0]
            $CRT = $CERT_PATHS[2]+".crt"
            $CRT_PATH = (Get-ChildItem -Path $CRT -File).FullName
            $PATH = $CRT_PATH.Remove($CRT_PATH.LastIndexOf("\")+1)
            $KEYSTORE = $CRT_PATH.SubString($CRT_PATH.LastIndexOf("\")+1)
            $KEYSTORE = $KEYSTORE.TrimEnd(4)
            $KEYSTORE = $KEYSTORE+".p12"
            $PATH = "$PATH$KEYSTORE"
            
            Invoke-Expression "openssl pkcs12 -export -out $PATH -inkey $KEY -in $CRT"
        }
    }
}
$GEN_CRL = Read-Host -Prompt "Create CRL?"

if ( $GEN_CRL -eq "y" -or $GEN_CRL -eq "Y") {
    $PATHS = (Get-ChildItem -Path $CA_OUT_DIR -File ).FullName
    openssl ca -gencrl -keyfile $PATHS[1] -cert $PATHS[0] > "$CRL_OUT_DIR\$DOMAIN.crl"
}