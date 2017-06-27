#TRUSTED 0c7d0e3bb973dffe94cd01bd0b6fde34b78925d9b56fb17cba64544e1bbb74ec4f547dec8a2f6adc1a3c7ef3751a7ae1800ae0e451526737db706ec1fe67fb0c26e84380f2b382f5a3e4cf703e0b107fd5c3595429ec1f1f4da91bfb86f6bbc83ff7a49b3039004cd3a5e376bbdd321ad0dd7f8642375f28ca017b85061a7adb6716266e568d727798776b054068504e88228acc14c086caa5db92029e8c328914e96a429728f44eff50dcc4841b0c9e9a17177ac67acbd89c20123890d6e0a2f20d83b6777cbe02161e39887192eff9cde53ff8e8d105d65a067463c9e1b318215d958d26ddbf5c4ae1e922ebf6fa75bfa9b2e80a6a618f18b104d6b9634c47a540fbb5100e8f0c69de17fd42e1797557df6a848fd8c4495370c0fc7e7829504d88df2fc0c70b2bacbbbbbfd2629f574f3ea3cd4536620af2855896cf5e3f9a482caa3b411b489d8b409beed224138b92dab3cc157bcf7645d981794f367499393fc83d092f5c755f130244facd6911cf1c97eacc9697b98367242efc8d992e82d460ae5dcfb78d34e31bd37e3c02f83e5a649667729d096bc52dd6112460274dfc4a2d46a286066d8a6a38fef4e096ac7d2680697dcf096f9a842c54d98d13cadf68dfe4f065ddcc3776a43fb87cd6245c5b01025594cc905223917d67e3dffa9cb976de9d9722ea7d7e5060f2285a346e4a6f6a408b53400175a03512ea96
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62574);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

  script_cve_id("CVE-2012-0726");
  script_bugtraq_id(53043);
  script_osvdb_id(81357);

  script_name(english:"IBM Tivoli Directory Server TLS NULL Cipher (uncredentialed check)");
  script_summary(english:"Checks response from server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote IBM Tivoli Directory Server contains an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The IBM Tivoli Directory Server hosted on the remote host supports TLS
NULL-MD5 or NULL_SHA ciphers.  This allows remote, unauthenticated
attackers to trigger unencrypted communication via the TLS handshake
protocol.

Note that this version of Directory Server likely has other
vulnerabilities (i.e., CVE-2012-0743), but Nessus has not checked
for those issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591272"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.47-ISS-ITDS-IF0047
  - 6.2.0.22-ISS-ITDS-IF0022
  - 6.3.0.11-ISS-ITDS-IF0011"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "ldap_search.nasl");
  script_require_ports("Services/ldap", 636);
  script_require_keys("SSL/Supported");


  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');
include("acap_func.inc");
include("ftp_func.inc");
include("http.inc");
include("imap_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("x509_func.inc");
include("xmpp_func.inc");


port = get_service(svc:'ldap', default:636, exit_on_fail:TRUE);

# Check vendor to make sure it's ITDS
vendor = get_kb_item_or_exit('LDAP/'+port+'/vendorName');
if ('IBM' >!< vendor)
  exit(0, 'The LDAP server listening on port '+port+' does not appear to be an IBM product.');

# Check for TLSv1 on remote port
tls10 = 0;
list = get_kb_list('SSL/Transport/'+port);
if (!isnull(list))
{
  list = make_list(list);
  foreach encap (list)
  {
    if(encap == ENCAPS_TLSv1)
    {
      tls10 = 1;
      break;
    }
  }
}

if (!tls10) exit(0, 'The LDAP server listening on port '+port+' does not appear to support TLS 1.0.');

soc = open_sock_ssl(port);
if (!soc) exit(0, 'open_sock_ssl() failed on port '+port+'.');

# Create a ClientHello record with NULL_MD5 and NULL_SHA ciphers
cipher  = ciphers['TLS1_CK_RSA_WITH_NULL_SHA'];
cipher += ciphers['TLS1_CK_RSA_WITH_NULL_MD5'];
helo = client_hello(
  version    : raw_string(0x03, 0x01), # TLSv1
  cipherspec : cipher,
  cspeclen   : mkword(strlen(cipher)),
  v2hello    : FALSE
);

# Send the ClientHello record
send(socket:soc, data:helo);
rec = recv_ssl(socket:soc);
close(soc);

if(isnull(rec)) audit(AUDIT_RESP_NOT, port);

# Check if a ServerHello is returned
msg = ssl_find(
  blob:rec,
  'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
  'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
);


# Patched server (6.3.0.11) returns a 'Handshake Failure' fatal alert.
# So the patched server didn't accept TLS1_CK_RSA_WITH_NULL_SHA, and it's not vulnerable.
if(isnull(msg))
  exit(0, 'The LDAP server listening on port '+port+' did not return a ServerHello message, and thus is probably not affected.');

# Vulnerable server (6.3.0.10) returns a ServerHello.
# Make sure the server selected TLS1_CK_RSA_WITH_NULL_SHA or TLS1_CK_RSA_WITH_NULL_MD5
chosen = mkword(msg['cipher_spec']);
if(chosen == ciphers['TLS1_CK_RSA_WITH_NULL_SHA'] || chosen == ciphers['TLS1_CK_RSA_WITH_NULL_MD5'])
  security_warning(port);
else audit(AUDIT_RESP_BAD, port);
