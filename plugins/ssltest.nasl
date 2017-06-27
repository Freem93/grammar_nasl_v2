#TRUSTED a95d40bb3fa1e26adc0f7b2dd63277f3ed25c84dcdcd34b0bee7def5617125cc3ea4cac3b15b1cedd607689b76b305e5fab008e736d401812e735007b77e28791cdd380afd2d443957585ab6c7b91b4aa1d1acaf63307e980d06a8b43ec6837f6116460236edd1c12f8f3c582176a8545b49f750c66bacebeccfd0d74faa3773d89748e01b07d86dc8c83c1fc0d05c5f12f90a6030fa66fc715bb81515fa844e05e4c956c10c4d14338e7bed3d7d3380b2ebd396a28125b0dbf2550cc7f0d6bfcd694834de774a6a211bc73d0b302c0f19fa57f423e256b69dbb7da66dccb3d628c9a1ea3a2b11cd5aaaebb925b6af170e7b8b0aab3dbb8fcfe908539008d8462ecd787bdd0772e7028866e46a23ee3daf48152c02216d8a6a8fbe8f25d2e75ce83a60ef96149eace6f75ec229595072b8a1741739dbc15d1c4f16b2c217cf578c16a1f6a3faade55bb75bd7ab8910765baa88597d058d07926fc981180cc456eb2aa03c176e179006dbc4717eb826de2f5057263ecc919cceb4709d02d123cdfae841ed93b11865f56ee208a91b8a24e81179426c1f78e4ddb00a7d7afdc3d1b55be05602af710d26a75ecd9ebf4d0f7e80cdc4012688ca08dfaa494addcc2ce3bf83c5140a151886e67e7ffe678ed9dc437578d79415358bd3e60b04eb124bf9ae840b839894668ca1dbacf97de35a2783fe9c8085f686eddef37f3d852ddb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11875);
 script_version("1.56");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/02");

 # CANs moved into CVE, moved back (bug 899) AH
 script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545", "CVE-2005-1247", "CVE-2005-1730");
 script_bugtraq_id(8732, 13359);
 script_osvdb_id(15805, 3684, 3686, 3943, 3949);
 script_xref(name:"RHSA", value:"2003:291-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:043");

 script_name(english:"OpenSSL ASN.1 Parser Multiple Remote DoS");
 script_summary(english:"Checks for the behavior of SSL");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a heap corruption vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running a version of OpenSSL that is older
than 0.9.6k or 0.9.7c.

There is a heap corruption bug in this version that might be exploited
by an attacker to execute arbitrary code on the remote host with the
privileges of the remote service.");
 script_set_attribute(attribute:"solution", value:
"If you are running OpenSSL, upgrade to version 0.9.6k or 0.9.7c or
newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("ssl_supported_versions.nasl", "macosx_version.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");

if ( get_kb_item("CVE-2003-0543") )
	exit(0);

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers, per user config");


get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

#####################################################################
# Microsoft spits an error on the packet below
# OpenSSL processes the packet...

myversion = raw_string(0x03,0x35);
mycipherspec = raw_string(0x00,0x00,0x62,0x04,0x00,0x80,0x00,0x00,0x63,0xa0,0x00,0xe9,0xda,0x00,0x64,0x02,0x00,0x80);
mychallenge =  raw_string(0x4E,0x45,0x53,0x53,0x55,0x53,0x4E,0x45,0x53,0x53,0x55,0x53,0x4E,0x9F,0x53,0x53);

req=client_hello(version:myversion, cipherspec:mycipherspec, challenge:mychallenge);

# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

send (socket:soc, data:req);
r = recv(socket:soc, length:800);

if (strlen(r) == 7)
	exit(0);

close(soc);

# some *other* SSL servers (not OpenSSL) respond to the nudge below
# we'll wean them out of the check

mymlen = 0;
mymtype = 0;
myversion = raw_string(0x31,0x35);
req=client_hello(mlen:mymlen, mtype:mymtype, version:myversion);

# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

send (socket:soc, data:req);
r = recv(socket:soc, length:65535);
if (r)
	exit(0);
close(soc);
#####################################################################


req = client_hello();

# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

send (socket:soc, data:req);
r = recv(socket:soc, length:65535);
if (r)
{
        # Thanks to Brad Hazledine for submitting report that:
        #> By removing weak ciphers from the SSLCipherSuite on Apache 1.3.29/mod_ssl
        #> 2.8.16/Openssl 0.9.7c it reports a false (vulnerable) version of openssl.
        # So, We'll look for error message 0x02 0x28 which denotes a failed handshake

    if ( (ord(r[5]) == 0x02) && (ord(r[6]) == 0x28) )
	exit(0);

        # Thanks to Steve (ssg4605 [at] yahoo.com)
        # for reporting anomalous behavior from apple xserve
    if ( (ord(r[1]) != 22) && (ord(r[1]) != 3) )
	exit(0);

    localcert = hex2raw(s: tolower("03CB0003C8308203C43082032DA003020102020100300D06092A864886F70D01010405003081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D301E170D3033313031303031313433395A170D3033313130393031313433395A3081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100DCA93F62D5088026DBBAD24A551F136289E39CA34AD9C0EEE0493A7E3103884572ADE53ACE68416FAB0CE44F3291A71A7FA3B89E6490E622F61B71140FCA37F2C5C8AD0D96CF1DEC454960B70582918BE96C5DEEC5B2E2A58CC8506FEAE7941C5DA8AF2EF6225F903350AB54743F48FE3322D7383FD6B2B619D2045476C7C6550203010001A382010430820100301D0603551D0E04160414FA4DD1D034857B04784BCAA4A708E004F2DFCD063081D00603551D230481C83081C58014FA4DD1D034857B04784BCAA4A708E004F2DFCD06A181A9A481A63081A3310B30090603550406130255533112301006035504081309536F6D6553544154453111300F06035504071308536F6D654349545931173015060355040A130E4E6573737573205363616E6E6572311C301A060355040B1313536563757269747920436F6D706C69616E6365311430120603550403130B4E657373757320557365723120301E06092A864886F70D01090116116E6F6F6E65406E6F77686572652E636F6D820100300C0603551D13040530030101FF300D06092A864886F70D0101040500038181001214A295E71DAF8EEAB4A9E19499B98D766A02A1F62B1F388C635A8D2A08B3F678CF952ACE0D57F8C4510C2F22C3CB3EBAFEBBE8E3DAF83183898EAA27858D0CFB1B4121C3FE750EEC740FFF46452B90D5473200B7121343990B185CF8698A2115B62D57CFD9C9EA220054EF4CF49513C25B63B07C38D126F4CAF98B37EAB0EC"));

    req2 = client_send_cert(certificate:localcert);
    send (socket:soc, data:req2);
    r2 = recv(socket:soc, length:65535);
    if (r2) {
        if ( ord(r2[6]) == 0x0A || ord(r2[6]) == 0x2a  || ord(r2[6]) == 0x2f)
	{               # the 7th byte must == 0x0A which is an error
           exit(0);                                      		# message stating "Unexpected message"
        } else {
           security_hole(port);
        }
    }
    # MA 2008-11-16: otherwise, the server abruptly closed the connection
    # after we sent the cert. Nothing proves this is a security bug, and
    # we do not report unknown problems without patch or workaround.
}
exit(0);

