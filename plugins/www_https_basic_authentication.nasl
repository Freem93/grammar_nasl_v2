#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(51080);
 script_version ("$Revision: 1.3 $");
 script_cvs_date("$Date: 2011/03/18 18:07:04 $");

 script_name(english: "Web Server Uses Basic Authentication over HTTPS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to transmit credentials using Basic
Authentication." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains web pages that are protected by
'Basic' authentication over HTTPS. 

While this is not in itself a security flaw, in some organizations,
the use of 'Basic' authentication is discouraged as, depending on the
underlying implementation, it may be vulnerable to account
brute-forcing or may encourage Man-in-The-Middle (MiTM) attacks." );
 script_set_attribute(attribute:"solution", value:

"Make sure that the use of HTTP 'Basic' authentication is in line with
your organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/12/08");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_summary(english: "Uses the results of webmirror.nasl");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);
if (get_port_transport(port) <= ENCAPS_IP)
 exit(0, "The web server on port "+port+" is not running on top of SSL/TLS.");

report = '';
for (i = 0; i < 64; i ++)
{
  url = get_kb_item(strcat("www/", port, "/content/basic_auth/url/", i));
  realm = get_kb_item(strcat("www/", port, "/content/basic_auth/realm/", i));
  if (strlen(realm) == 0 || strlen(url) == 0) break;
  report += strcat(url, ':/ ', realm, '\n');
}

if (strlen(report) > 0)
 security_note(port:port, extra:'\nThe following pages are protected :\n\n'+report);
