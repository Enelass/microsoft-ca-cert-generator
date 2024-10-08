#!/bin/bash
#############################################################################################
# AUTHOR: FlORIAN BIDABE																	#
#																							#
# VERSION 1.2.c  RELEASE DATE January 22, 2016    											#
# This script helps you with generating SSL material from an internal Micorosft CA			#
# 1) Define your variables and CA Bundle in this script	(between < and >)					#
# 2) Run the script																			#
#																							#
# Process:																					#
# 1- Generate or import CSR																	#
# 2- Submit CSR and specify additional Subject Alternate Name (SAN)							#
# 3- Collect certificate from your CA (Certificate Authority)	==> MANUAL					#
# 4- Generate SSL material and format														#
#																							#
#																							#
# Tested on:																				#
# Certificate Authority: Windows Server 2008 R2 / 2012										#
# Client: Windows 10 with cygwin (cURL, OpenSSL, clip)						                #
#############################################################################################


#_____________________________________________________________________________________________
########################################   Variables  ########################################

# Internal Env Settings
MSCA='winserver.company.com'  		   # Internal Microsoft Certification Authority FQDN
CertTplt='WebServerINT'		           # Internal Cert Template Name
UA='Mozilla%2F5.0+%28Windows+NT+6.3%3B+WOW64%3B+Trident%2F7.0%3B+rv%3A11.0%29+like+Gecko' # A Random user agent...
Domain='company.com' 		           # Used for signing both hostname and FQDN
Username=""$Domain"\\yourusername"	   # Required for certificate submission
Password='yourpassword'			       # Can be commented to be interactive

# Email Settings
mailserver="smtp.company.com"
mailport=25
to="ServiceDesk@company.com"
cc="Security@company.com"
bcc="myself@company.com"

MailTemplate="
Please create and assign a ticket the Security/Certificate Team to track this certificate request.
The Request ID has been attached in the email (HTTP Response)
Date: `date "+%Y-%m-%d %H:%M"`
Issuer: "$Username"

Information Systems
Phone Number:
Company Address:"

# SaveIn=~/Desktop/Certs
SaveIn=~/Certificates/NewRequests #Save the file in Team's OneDrive folder
FileMgr=explorer	# File Manager

# OpenSSL CFG settings for CSR (Code Signing Request) submission
Country='AU'
State='QLD'
City='Ninderry'
Company='GMBH Pty Ltd'
UrOrg='Information Systems'

# Internal Base64 Root and Intermediate CAs (Used for creating PEM and PKCS12 bundles)
IntRoot=`echo '
-----BEGIN CERTIFICATE-----
MII_Base64_RootCertificateAuthority
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MII_Base64_IntermCerticateAuthority
-----END CERTIFICATE-----'`

#_____________________________________________________________________________________________
######################################## Requirements ########################################

# OpenSSL    
type openssl > /dev/null 2>&1 || { 
    echo "Cannot find OpensSSL, it is required to generate certificates.  Aborting..." 1>&2
    exit 1
}

# cURL
type curl > /dev/null 2>&1 || { 
    echo "Cannot find cURL, it is required to submit certificates.  Aborting..." 1>&2
    exit 1
}

#_____________________________________________________________________________________________
######################################## Optional ############################################

# Clip
type clip > /dev/null 2>&1 || { 
    echo -e "Cannot find clip ! it is required to save the CSR into your clipboard.\n Attempting to install it in System32..." 1>&2
    cd 'C:\Windows\system32'; curl -L -O "https://www.dropbox.com/s/cvkxeak0j0wtjj0/clip.exe"
}

# GNU Email
type email > /dev/null 2>&1 || { 
    echo -e "Cannot find GNU email ! it is required to send an email to notify a security administrator and issue the certificate." 1>&2
}

# Internet Explorer
if [ -f '/cygdrive/c/Program\ Files/Internet\ Explorer/iexplore.exe' ]; then iexplore='/cygdrive/c/Program\ Files/Internet\ Explorer/iexplore.exe'
    else iexplore=$(sed 's| |\\ |g' <<< "$(find /cygdrive/ -name "iexplore.exe" -exec sh -c 'printf "%s\n" "$1"; kill "$PPID"' bash {} \;)") 
fi


    #_____________________________________________________________________________________________
########################################   Functions  ########################################

gencsr() {
    # Generate Config File (CFG) for Code Signing Request (CSR)
    echo "`date "+%Y-%m-%d %H:%M:%S"` - User Option: 1) Generate CSR and Private Key" >> $LOGS
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Parsing Config File (CFG)" >> $LOGS

    # Set additional SAN (for CFG)
    local n=1 #Enter Loop
    local SAN
    SAN="subjectAltName = DNS:"$Hostname", DNS: "$Hostname.$Domain""
    while  (( n > 0 && n < 4 )); do
        echo -e "\n\n\nDo you want to set an additional Subject Alternate Name (Config File) ? (No)"
        echo -e "Current SAN:\n"$SAN""
        echo -e "Select your choice and press [ENTER]\n\t[1] Add an IP address\n\t[2] Add an hostname\n\t[3] Reset SAN to default\n\t[*] Continue"
        read -p "Option number : " n
        case $n in
            1) # Add Extra IP for SAN
                while [[ -z ${IP+x} || $? != 0 ]]; do
                    read -p "What is the server's IP address: " IP
                    [[ "$IP" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]
                    if [ $? != 0 ]; then echo "This IP address ("$IP") does not look quite right! Please try again..."; fi
                    [[ "$IP" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]
                done
                SAN+=", IP:"$IP", DNS:"$IP""; unset IP
                ;;
            2) # Add extra DNS name to SAN
                while [[ -z ${extraSAN+x} ||  $? != 0 ]]; do
                    read -p "Specify a Fully Qualified Domain Name for the extra SAN : " extraSAN
                    [[ "$extraSAN" =~ ^[A-Za-z0-9.-]+$ ]]
                    if [ $? != 0 ]; then echo "This syntax is incorrect! Please try again..."; fi
                    [[ "$extraSAN" =~ ^[A-Za-z0-9.-]+$ ]]
                done
                SAN+=", DNS:"$extraSAN""; unset extraSAN
                ;;
            3) SAN="subjectAltName = DNS:"$Hostname", DNS:"$Hostname.$Domain"" ;;
            *) n=4 ;; #Quit loop
        esac
    done
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Subject Alternate Name (CFG): "$SAN"" >> $LOGS

    echo "
    [ req ]
    default_md = sha512
    default_bits = 2048
    default_keyfile = "$Hostname"_pk8.key
    distinguished_name = req_distinguished_name
    encrypt_key = no
    prompt = no
    string_mask = nombstr
    req_extensions = v3_req
    input_password = password
    output_password = password

    [ v3_req ]
    basicConstraints = CA:false
    keyUsage = digitalSignature, keyEncipherment, dataEncipherment
    extendedKeyUsage = serverAuth, clientAuth
    "$SAN"

    [ req_distinguished_name ]
    countryName = "$Country"
    stateOrProvinceName = "$State"
    localityName = "$City"
    0.organizationName = "$Company"
    organizationalUnitName = "$UrOrg"
    commonName = "$Hostname.$Domain"" > "$Hostname".cfg
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Config File (CFG) parsed ! Located at `pwd`/"$Hostname".cfg" >> $LOGS

    # Generate CSR and private key (PKCS8) & convert Private Key (PKCS8 to PKCS1)
    echo -e "\n\nGenerating Code Signing Request (CSR) and Private Key (PKCS#8)..."
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Generating Code Signing Request (CSR) and Private Key (PKCS#8): "$Hostname".csr and "$Hostname"_pk8.key"  >> $LOGS
    openssl req -out "$Hostname".csr -new -nodes -config "$Hostname".cfg > /dev/null 2>&1

    echo "Generating private key (PKCS#1)..."
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Generating Private Key (PKCS#1): "$Hostname"_pk1.key"  >> $LOGS
    openssl rsa -in "$Hostname"_pk8.key -out "$Hostname"_pk1.key > /dev/null 2>&1

    if [ $? != 0 ]; then
        echo "An error has occured ! Exiting..., Please consult the logs"
        echo "`date "+%Y-%m-%d %H:%M:%S"` - Error on generating CSR or Private Keys"  >> $LOGS
        exit 1
    fi
}

importcsr() {
    # Importing Code Signing Request (CSR)
    echo "`date "+%Y-%m-%d %H:%M:%S"` - User Option: 2) Import CSR" >> $LOGS
    local n

    printf "\033c"
    echo -e "This function automates IIS7 certificate generation for "$Company $UrOrg"
\tServer name:\t"$Hostname"\n\tFQDN:\t\t"$Hostname"."$Domain"\n"
    echo "Importing Code Signing Request..."

    #Verify CSR 
    # If CSR is not Base 64
    openssl req -text -noout -verify -in *.csr > /dev/null 2>&1
    while [ $? != 0 ]; do
        # Check if there are multiple csr files
        while [ $(find -name "*.csr" | wc -l) != 1 ]; do
            echo -e "\nError, $(find -name "*.csr" | wc -l) CSR(s) found ! One CSR is required..."
            echo "Please import your CSR in "$SaveIn" and make sure the extension is *.csr"
            echo "`date "+%Y-%m-%d %H:%M:%S"` - WARNING: There should be one CSR only in "$SaveIn"" >> $LOGS
            $FileMgr . 2> /dev/null
            read -p "Press any key to continue...";
        done
        openssl req -text -noout -verify -inform DER -in *.csr > /dev/null 2>&1
        if [ $? == 0 ]; then
            echo -e "\n\nThis Code Signing Request is not a Base64 request !\nConverting DER request to Base64... Success !"
            mv *.csr "$Hostname".dcsr
            openssl req -out "$Hostname".csr -outform PEM -inform DER -in *.dcsr
            echo "`date "+%Y-%m-%d %H:%M:%S"` - DER CSR detected, converting to Base64... Success !" >> $LOGS
            echo "`date "+%Y-%m-%d %H:%M:%S"` - DER CSR: "$Hostname".dcsr\tBase64 CSR: "$Hostname".csr" >> $LOGS            
        else 
            openssl req -text -noout -verify -in *.csr > /dev/null 2>&1
            if [ $? != 0 ]; then 
                echo -e "Your CSR file is not valid or is corrupted!\nPlease import your CSR in "$SaveIn"..."
                echo "`date "+%Y-%m-%d %H:%M:%S"` - ERROR: This CSR is invalid, it is neither a DER or Base64 CSR" >> $LOGS
                $FileMgr . 2> /dev/null
                read -p "Press any key to continue..."; fi
        fi
        openssl req -text -noout -verify -in *.csr > /dev/null 2>&1
    done

    # Optional: Converting a Base64 CSR to DER
    if [ ! -f *.dcsr ]; then
        openssl req -outform DER -inform PEM -in *.csr -out "$Hostname".dcsr > /dev/null 2>&1
        if [ $? == 0 ]; then
            echo "`date "+%Y-%m-%d %H:%M:%S"` - Base64 CSR detected, converting to DER... Success !" >> $LOGS
            echo "`date "+%Y-%m-%d %H:%M:%S"` - DER CSR: "$Hostname".dcsr\tBase64 CSR: "$Hostname".csr" >> $LOGS
        fi
    fi
}

urlencode() {
    local data
    if [[ $# != 1 ]]; then return 1; fi
    data="$(curl -s -o /dev/null -w %{url_effective} --get --data-urlencode "$1" "")"
    if [[ $? != 3 ]]; then return 2; fi
    echo "${data##/?}"; return 0
}   

getcert() {
	######################### 3- Get Certificate ########################
	echo -e "\n\n`date "+%Y-%m-%d %H:%M:%S"` - Step 3: Getting the Certifiate"  >> $LOGS

	printf "\033c"
	echo -e "This function automates IIS7 certificate generation for "$Company $UrOrg"
	\tServer name:\t"$Hostname"\n\tFQDN:\t\t"$Hostname"."$Domain"\n"

	echo -e "Open \"Certificate Authority\" in a Management Console (MMC) and connect to "$MSCA"\nVerify that your certificate request is in "Pending Requests".\nIssue the Certificate (Right Click, All Tasks, Issue)\nNavigate to "Issue Certificates", order by Request ID (Descending) and export it (Open / Details / Copy To File) 'Base-64 Encoded X.509' to "$SaveIn".\nThe file must have a *.cer extension\n"

	read -p "Press any keys when the certificate (*.cer) has been place in "$SaveIn""


	#Verify Certificate
	openssl x509 -text -noout -in "$Hostname".cer > /dev/null 2>&1
	while [ $? != 0 ]; do
		# Verify that there is only one certificate
		while [ $(find -name "*.cer" | wc -l) == 0 ]; do
			echo "Please import certificate (*.cer) in "$SaveIn""
			if [ -z ${Manual+x} ]; then $FileMgr . 2> /dev/null
			else
				#If the certificate has been uploaded using a browser, it can be retrieved using the browser
				if [ -z ${iexplore+x} ]; then echo "Open "https://"$MSCA"/certsrv/certckpn.asp""    
				else eval $iexplore "https://"$MSCA"/certsrv/certckpn.asp"; fi
			fi
			read -p "Press any key to continue..."; done
		while [ $(find -name "*.cer" | wc -l) != 1 ]; do
			echo "Error, $(find -name "*.cer" | wc -l) certificates found in "$SaveIn"! Please clean it up !"
			$FileMgr . 2> /dev/null
			read -p "Press any key to continue..."
		done

		# Verify Certificate Integrity and format
		mv *.cer "$Hostname".cer
		echo -e "`date "+%Y-%m-%d %H:%M:%S"` - Certificate found at `pwd`/"$Hostname".cer"  >> $LOGS
		openssl x509 -text -noout -in *.cer  > /dev/null 2>&1
		if [ $? != 0 ]; then
			openssl x509 -inform der -text -noout -in *.cer > /dev/null 2>&1 # Test if DER
			if [ $? == 0 ]; then # Convert DER to Base64
				mv *.cer "$Hostname".der
				openssl x509 -inform der -in "$Hostname".der -out "$Hostname".cer  > /dev/null 2>&1
				echo "`date "+%Y-%m-%d %H:%M:%S"` - DER certificate detected, converting to Base64... Success !" >> $LOGS
				echo "`date "+%Y-%m-%d %H:%M:%S"` - DER certificate: "$Hostname".der\tBase64 certificate: "$Hostname".cer" >> $LOGS 
			else
				echo -e "This certificate is invalid or corrupted!\nPlease import it again in "$SaveIn"..."
				echo "`date "+%Y-%m-%d %H:%M:%S"` - ERROR: The certificate is invalid, it is neither a DER or Base64 certificate" >> $LOGS
				read -p "Press any key to continue..."
			fi
			openssl x509 -text -noout -in *.cer  > /dev/null 2>&1
		fi
	done

	# Optional: Converting a Base64 CSR to DER
	if [ ! -f *.der ]; then
		openssl x509 -outform der -in "$Hostname".cer -out "$Hostname".der  > /dev/null 2>&1
		if [ $? == 0 ]; then
				echo "`date "+%Y-%m-%d %H:%M:%S"` - Base64 Certificate detected, converting to DER... Success !" >> $LOGS
				echo "`date "+%Y-%m-%d %H:%M:%S"` - DER Certificate: "$Hostname".dcsr\tBase64 Certificate: "$Hostname".csr" >> $LOGS
		fi
	fi

	###################### 4- Generating SSL material #########################
	# Creating PEM certificate chain
	echo -e "`date "+%Y-%m-%d %H:%M:%S"` - Step 4 (Final): Generating SSL material"  >> $LOGS
	if [ -f ""$Hostname"_pk1.key" ]; then
		cat "$Hostname"_pk1.key > ""$Hostname".pem"
		cat *.cer >> ""$Hostname".pem"
		echo -e "`date "+%Y-%m-%d %H:%M:%S"` - A PEM has been generated containing the Private Key and entire certificate chain: Public Key for "$Hostname" and CA Bundle (intermediate and root certificates) "  >> $LOGS
	else
		cat *.cer > ""$Hostname".pem"
		echo -e "`date "+%Y-%m-%d %H:%M:%S"` - A PEM has been generated containing the entire certificate chain: Public Key for "$Hostname" and CA Bundle (intermediate and root certificates)"  >> $LOGS
		echo -e "`date "+%Y-%m-%d %H:%M:%S"` - As the CSR was imported, no private key can be included in the PEM container"  >> $LOGS
	fi
	echo "$IntRoot" >> ""$Hostname".pem"
	sed -i '/^$/d' "$Hostname".pem"" # Delete empty lines

	# Converting PEM certificate chain to PKCS#12 (.pfx)"
	cat *.pfx 2> /dev/null #Enter Loop
	while [ $? != 0 ]; do
		if [ -f "$Hostname"_pk1.key ]; then openssl pkcs12 -export -out ""$Hostname".pfx" -in ""$Hostname".pem"
		else openssl pkcs12 -export -nokeys -out ""$Hostname".pfx" -in ""$Hostname".pem"
		fi
	done
	echo -e "`date "+%Y-%m-%d %H:%M:%S"` - A PKCS12 (.pfx, .p12) has been generated from the PEM"  >> $LOGS
	echo -e "`date "+%Y-%m-%d %H:%M:%S"` - Ending gracefully :)"  >> $LOGS
	mv ../"$Hostname" ../../INTERNAL/
	cd ../../INTERNAL/"$Hostname"
	$FileMgr . 2> /dev/null
	exit 0
}

#_____________________________________________________________________________________________
########################################      GUI     ########################################

printf "\033c"
echo -e "This function automates IIS7 certificate generation for "$Company $UrOrg""

# Set Hostname and IP address
Hostname="$1"; [[ "$Hostname" =~ ^[-A-Za-z0-9]+$ ]]
while [ $? != 0 ]; do
    read -p "Specify the server hostname (Not FQDN !): " Hostname
    [[ "$Hostname" =~ ^[-A-Za-z0-9]+$ ]]
    if [ $? != 0 ]; then echo "This hostname syntax is incorrect, try again !"; fi
    [[ "$Hostname" =~ ^[-A-Za-z0-9]+$ ]]
done
LOGS=""$Hostname".logs"

# Set destination folder for SSL material
SaveIn+="/"$Hostname"";

if [ -d "$SaveIn" ]; then
    echo "A folder named "$Hostname" already exists, Start over (delete existing materials) or quit ?"
    echo -e "Select your choice and press [ENTER]\n\t[1] Start Over (Delete existing content)\n\t[2] Resume (Certificate Generation)\n\t[*] Quit"
read -p "Option number : " n
    case $n in
        1) rm -R "$SaveIn" > /dev/null 2>&1; mkdir -p "$SaveIn" > /dev/null 2>&1; cd "$SaveIn" ;;
        2) cd "$SaveIn"; getcert "$@" ;;
        *) echo "Aborting..."; exit 0 ;;
    esac
else mkdir -p "$SaveIn"; cd "$SaveIn" 
fi

###LOGGING GUI###
echo "`date "+%Y-%m-%d %H:%M:%S"` - Starting... Path: `pwd`" > $LOGS
echo "`date "+%Y-%m-%d %H:%M:%S"` - OpenSSL Version: `openssl version`" >> $LOGS
echo "`date "+%Y-%m-%d %H:%M:%S"` - cURL Version: `head -n 1 <(curl --version)`" >> $LOGS
echo "`date "+%Y-%m-%d %H:%M:%S"` - Server name: "$Hostname" FQDN: "$Hostname"."$Domain"" >> $LOGS

######################### 1- Get CSR  ###############################
echo -e "\n\n`date "+%Y-%m-%d %H:%M:%S"` - Step 1: Code Signing Request"  >> $LOGS
printf "\033c"
echo -e "This function automates IIS7 certificate generation for "$Company $UrOrg"
\tServer name:\t"$Hostname"\n\tFQDN:\t\t"$Hostname"."$Domain"\n"
echo -e "\nCode Signing Request (CSR):\n\tYou can generate a CSR and Private key or import a CSR (generated by an appliance and downloaded by you).
\tPlease note that importing a CSR means that the private key remains on the appliance or vendor's site.
\tSelect your choice and press [ENTER]\n\t[1] Generate CSR and Private Key\n\t[2] Import CSR\n\t[*] Quit"
read -p "Option number : " n
case $n in 
    1) gencsr "$@" ;;
    2) importcsr "$@" ;;
    *) echo "`date "+%Y-%m-%d %H:%M:%S"` - User Option: Quit" >> $LOGS; echo "Aborting..."; exit 0 ;;
esac

#########################  2- Submit CSR ############################
echo -e "\n\n`date "+%Y-%m-%d %H:%M:%S"` - Step 2: Submitting CSR"  >> $LOGS

# Capture Attempt: Session ID cookie
echo "`date "+%Y-%m-%d %H:%M:%S"` - Capturing Session ID cookie from "$MSCA"" >> $LOGS
echo 'Capturing ASP Session ID (Cookie)...'
if [ -z "$Password" ]; then echo "What is the password for $Username ?: "; read -s Password; fi
RE=': ([^;]*);'     #Regex to capture ASP Session ID from cookie string
while read l; do [[ $l =~ $RE ]] && AspSession="${BASH_REMATCH[1]}"; done <<<"$(grep "Cookie" <<< "$(curl --silent -Iku "$Username":"$Password" --ntlm  https://"$MSCA"/certsrv/certrqxt.asp)")" 

# If fail capturing cookie ==> Manual (Browser-Mode)
if [ -z "$AspSession" ]; then
    echo "`date "+%Y-%m-%d %H:%M:%S"` - ERROR: Cannot capture Session ID cookie, failover to browser-mode..." >> $LOGS
    echo "WARNING: Cannot capture Session ID cookie for "$MSCA", failover to browser-mode...\nPlease verify your credentials to connect to $MSCA\n\n"
    echo "Paste CSR directly in internal CA web interface"
    echo -e "\tConfirm the Subject Alternate Name field before submission !\n\tNote that the CSR may already include SAN(s) !
    Current Subject: `openssl req -in *.csr -noout -text | grep "Subject:"`
    Current SAN: `openssl req -in *.csr -noout -text | grep "DNS:"`"
    clip <<< "$(cat *.csr 2> /dev/null)" ; Manual=1
    echo -e "Please upload your Code Signing Request to your Internal Certificate Authority ("$MSCA") :"
    if [ -z ${iexplore+x} ]; then
        echo "Open "https://"$MSCA"/certsrv/certrqxt.asp" in a browser"
    else
        eval $iexplore "https://"$MSCA"/certsrv/certrqxt.asp" &
        echo "Press any key to continue..." ; read
    fi 
fi

# If Session ID cookie sucessfully captured  ==> Automatic (cURL-Mode)
if [ -z ${Manual+x} ]; then
    echo "ASP cookie captured !"
    # Set additional SAN (for cURL)
    echo -e "\n\nConfirm the Subject Alternate Name before submission:
    Current Common Name: `openssl req -in *.csr -noout -text | grep "Subject:"`
    Current SAN: `openssl req -in *.csr -noout -text | grep "DNS:"`"
    echo -e "\nDo you want to add a Subject Alternate Name (No) ?\nSelect your choice and press [ENTER]\n\t[1] Yes\n\t[*] No\n"
    read -p "Option number : " n
    case $n in
        1)  unset n;  n=1 #Enter Loop
            unset SAN; SAN="san%3Adns%3D"$Hostname"%26dns%3D"$Hostname.$Domain""
            while  (( n > 0 && n < 4 )); do
                echo -e "\n\n\nDo you want to set an additional Subject Alternate Name ? (No)"
                echo -e "Current SAN (URL Encoded): "$SAN""
                echo -e "Select your choice and press [ENTER]\n\t[1] Add an IP address\n\t[2] Add an hostname\n\t[3] Reset SAN to default\n\t[*] Continue"
                read -p "Option number : " n
                case $n in
                    1) # Add Extra IP for SAN
                        while [[ -z ${IP+x} || $? != 0 ]]; do
                            read -p "What is the server's IP address: " IP
                            [[ "$IP" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]
                            if [ $? != 0 ]; then echo "This IP address ("$IP") does not look quite right! Please try again..."; fi
                            [[ "$IP" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]
                        done
                        SAN+="%26dns%3D"$IP""; unset IP
                        ;;
                    2) # Add extra DNS name to SAN
                        while [[ -z ${extraSAN+x} ||  $? != 0 ]]; do
                            read -p "Specify a Fully Qualified Domain Name (FQDN) for the extra SAN: " extraSAN
                            [[ "$extraSAN" =~ ^[A-Za-z0-9.-]+$ ]]
                            if [ $? != 0 ]; then echo "This syntax is incorrect! Please try again..."; fi
                            [[ "$extraSAN" =~ ^[A-Za-z0-9.-]+$ ]]
                        done
                        SAN+="%26dns%3D"$extraSAN""; unset extraSAN
                        ;;
                    3) SAN="san%3Adns%3D"$Hostname"%26dns%3D"$Hostname.$Domain"" ;;
                    *) n=4 ; SAN+='%0D%0A' ;; #Quit loop
                esac
            done
            ;;
        *) ;;
    esac

    CertFormat=$(sed 's| |+|g' <<< $(sed 's|+|%2B|g' <<< $(sed 's|/|%2F|g' <<< $(sed ':a;N;$!ba;s/\n/%0D%0A/g' *.csr))))
    Date=$(sed 's|%20|+|g' <<< $(urlencode "`date '+%m/%d/%Y,%r'`"))
    cURLData="Mode=newreq&CertRequest="$CertFormat"&CertAttrib="$SAN"CertificateTemplate%3A"$CertTplt"%0D%0AUserAgent="$UA"%0D%0A&FriendlyType=Saved-Request+Certificate+%28"$Date"%29&ThumbPrint=&TargetStoreFlags=0&SaveCert=yes"
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Generating and encoding cURL POST data..." >> $LOGS

    echo -e "Injecting crafted POST request to Internal CA using cURL and NTLM authentication...\n"
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Injecting crafted POST request to Internal CA using cURL and NTLM authentication..." >> $LOGS
    InjectCmd="curl --silent -i -ku '$Username':'$Password' --ntlm '"https://"$MSCA"/certsrv/certfnsh.asp"' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Connection: keep-alive' -H 'Cookie: "$AspSession"' \
    -H 'Host: "$MSCA"' \
    -H 'Referer: https://"$MSCA"/certsrv/certrqxt.asp' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
    -H 'Content-Type: application/x-www-form-urlencoded' --data '"$cURLData"'"
    InjectCmdLog=`echo $InjectCmd | sed "s|"$Password"|<password>|g"`
    echo "`date "+%Y-%m-%d %H:%M:%S"` - Command: "$InjectCmdLog"" >> $LOGS
    echo "`date "+%Y-%m-%d %H:%M:%S"` - BEGIN HTTP REPLY: Consult "$Hostname".html" >> $LOGS
    eval "$InjectCmd" &> "$Hostname.html"
    echo "`date "+%Y-%m-%d %H:%M:%S"` - END HTTP REPLY" >> $LOGS
    if [ $? != 0 ] || grep -q 'Access Denied' "$Hostname.html" || grep -q 'Denied by Policy Module' "$Hostname.html"; then
        echo -e "Injection seems to have gone wrong! Please verify if the request is missing in the Certificate Authority Snap-In on "$MSCA""
        echo -e "Consult Log file for analysis of the cURL query: it might be malformed!"
        echo -e "Log file location: `pwd`/"$LOGS""
        echo "`date "+%Y-%m-%d %H:%M:%S"` - Injection has failed !" >> $LOGS
        exit 1
    fi
fi

email "$to" -cc "$cc" -bcc "$bcc" -a "$Hostname".html -s "Certificate Request: Please issue $Hostname.$Domain certificate" -r $mailserver -p $mailport <<< "$MailTemplate"
echo "An email has been sent to the parent company (You are in CC) ! Once approved, please connect to "$MSCA" to retrieve your certificate using the Certificate Authority via mmc.exe"
echo "Once retrieved, open again this utility, enter the same hostname ("$Hostname") and resume operations: this will generates cryptographic material bundles (PEM, #PKCS12... etc.)"
echo "Please take notes of password you set to access the private key on the PKCS12 material"
