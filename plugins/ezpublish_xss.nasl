#
# written by K-Otik.com <ReYn0@k-otik.com>
#

# ezPublish Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (5/05/09)

include("compat.inc");

if (description)
{
 script_id(11449);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");

 script_cve_id("CVE-2003-0310");
 script_bugtraq_id(7137, 7138);
 script_osvdb_id(6554, 6563, 50553);

 script_name(english:"ez Publish Multiple XSS");
 script_summary(english:"Determine if ezPublish is vulnerable to xss attack");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to cross-site scripting
attacks.");
 script_set_attribute(attribute:"description", value:
"ezPublish 2.2.7 has a cross-site scripting bug. An attacker may use it
to perform a cross-site scripting attack on this host.

In addition to this, another flaw may allow an attacker store hostile
HTML code on the server side, which will be executed by the browser of
the administrative user when he looks at the server logs.");
 script_set_attribute(attribute:"solution", value:"Upgrade to a newer version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2016 k-otik.com");

 script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


foreach d (cgi_dirs())
{
 url = string(d, "/search/?SectionIDOverride=1&SearchText=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if("Search results for: '<script>window.alert(document.cookie);</script>" >< buf)
 {
   security_warning(port:port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}

