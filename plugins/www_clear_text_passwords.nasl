#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26194);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");

 script_name(english:"Web Server Transmits Cleartext Credentials");
 script_summary(english:"Uses the results of webmirror.nasl");
 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server might transmit credentials in cleartext.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains several HTML form fields containing
an input of type 'password' which transmit their information to
a remote web server in cleartext.

An attacker eavesdropping the traffic between web browser and 
server may obtain logins and passwords of valid users.");
 script_set_attribute(attribute:"solution", value:
"Make sure that every sensitive form transmits content over HTTPS.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_cwe_id(
   522,	# Insufficiently Protected Credentials
   523,	# Unprotected Transport of Credentials
   718,	# OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management	
   724,	# OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management
   928, # Weaknesses in OWASP Top Ten 2013
   930  # OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/28");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

kb = get_kb_item_or_exit("www/" + port + "/ClearTextPasswordForms");
if ( kb )
{
  if (report_verbosity > 0)
  {
    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:kb);
    security_note(port:port, extra:kb);
  }
  else
  {
    if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, 
						value:"The remote web server might transmit credentials in cleartext.");
    security_note(port);
  }
}
