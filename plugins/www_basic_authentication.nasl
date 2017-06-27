#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34850);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");


 script_name(english:"Web Server Uses Basic Authentication Without HTTPS");
 script_summary(english:"Uses the results of webmirror.nasl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to transmit credentials in cleartext.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains web pages that are protected by 'Basic'
authentication over cleartext.

An attacker eavesdropping the traffic might obtain logins and passwords
of valid users.");
 script_set_attribute(attribute:"solution", value:
"Make sure that HTTP authentication is transmitted over HTTPS.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_cwe_id(
  319, # Cleartext Transmission of Sensitive Information
  928, # Weaknesses in OWASP Top Ten 2013
  930, # OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
  934  # OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);
if (get_port_transport(port) > ENCAPS_IP)
 exit(0, "The web server on port "+port+" is running on top of SSL/TLS.");

report = '';
for (i = 0; i < 64; i ++)
{
  url = get_kb_item(strcat("www/", port, "/content/basic_auth/url/", i));
  realm = get_kb_item(strcat("www/", port, "/content/basic_auth/realm/", i));
  if (strlen(realm) == 0 || strlen(url) == 0) break;
  report += strcat(url, ':/ ', realm, '\n');
}

if (strlen(report) > 0)
{
 report = '\n' + 'The following web pages use Basic Authentication over an unencrypted' + 
          '\n' + 'channel :' +
          '\n' +
          '\n' + report;


 if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
 security_note(port:port, extra:report);
}
