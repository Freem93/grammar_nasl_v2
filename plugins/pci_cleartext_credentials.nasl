#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56208);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_name(english:"PCI DSS Compliance : Insecure Communication Has Been Detected");
 script_summary(english:"Insecure communication detected.");
 
 script_set_attribute(attribute:"synopsis", value:
"An insecure port, protocol, or service has been detected.");
 script_set_attribute(attribute:"description", value:
"Applications that fail to adequately encrypt network traffic using
strong cryptography are at increased risk of being compromised and
exposing cardholder data. An attacker who is able to exploit weak
cryptographic processes can gain control of an application or even
gain cleartext access to encrypted data.");
 script_set_attribute(attribute:"solution", value:
"Properly encrypt all authenticated and sensitive communications.");
 script_set_attribute(attribute:"risk_factor", value:"Medium");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_family(english:"Policy Compliance");

 script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

 script_dependencies(
  "xdmcp.nasl",
  "sambar_plaintext.nasl",
  "rexecd.nasl",
  "cvs_detect.nasl",
  "rlogin.nasl",
  "rsh.nasl",
  "acap_plaintext_authentication.nasl",
  "amqp_plaintext_authentication.nasl",
  "12planet_chat_server_plaintext_password.nasl",
  "ftps_plaintext_fallback.nasl",
  "nut_plaintext_authentication.nasl",
  "smb_password_encryption_disabled.nasl",
  "asip-status.nasl",
  "xmpp_plaintext_authentication.nasl",
  "subversion_plaintext_authentication.nasl",
  "snmp_settings.nasl",
  "mssqlserver_detect.nasl",
  "ldap_detect.nasl",
  "www_basic_authentication.nasl", 
  "ftp_clear_text_credentials.nasl", 
  "telnet_clear_text.nasl", 
  "www_clear_text_passwords.nasl", 
  "pop3_unencrypted_cleartext_logins.nasl", 
  "smtp_unencrypted_cleartext_logins.nasl", 
  "imap_unencrypted_cleartext_logins.nasl", 
  "pop2_unencrypted_cleartext_logins.nasl",
  "nntp_unencrypted_cleartext_logins.nasl",
  "X_open.nasl",
  "remote_pc_detect.nasl",
  "cheopsNG_clear_text_password.nasl"
 );
 exit(0);
}

include("audit.inc");

if ( ! get_kb_item("Settings/PCI_DSS" )) audit(AUDIT_PCI);

list = get_kb_list("PCI/ClearTextCreds/*");
if (isnull(list)) audit(AUDIT_KB_MISSING, 'PCI/ClearTextCreds/*');

foreach key ( keys(list) ) 
{
  report = NULL;
  sublist = get_kb_list(key);
  if ( isnull(sublist) ) continue;
  sublist = make_list(sublist);
  foreach item ( sublist ) 
  {
   report += item + '\n';
  }
  port = int(key - "PCI/ClearTextCreds/");
  security_warning(port:port, extra:report);
}
