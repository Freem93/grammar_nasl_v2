#
#  Written by K-Otik.com <ReYn0@k-otik.com>
#
#  DCP-Portal Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#
#  Modified by David Maciejak <david dot maciejak at kyxar dot fr>
#  add ref:  Alexander Antipov <antipov@SecurityLab.ru>

# Changes by Tenable:
# - Revised plugin title (4/28/09)

include("compat.inc");

if (description)
{
 script_id(11446);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

 script_cve_id("CVE-2003-1536", "CVE-2004-2511", "CVE-2004-2512");
 script_bugtraq_id(7141, 7144, 11338, 11339, 11340);
 script_osvdb_id(7021, 7022, 10585, 10586, 10587, 10588, 10589, 10590, 10591, 11405);

 script_name(english:"DCP-Portal Multiple Script XSS");
 script_summary(english:"Check for DCP-Portal XSS flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"The version of DCP-Portal installed on the remote host fails to
sanitize input to the script 'calendar.php' before using it to
generate dynamic HTML, that could let an attacker execute arbitrary
code in the browser of a legitimate user.

It may also be affected by HTML injection flaws, which could let an
attacker to inject hostile HTML and script code that could permit
cookie-based credentials to be stolen and other attacks, and HTTP
response splitting flaw, that could let an attacker to influence or
misrepresent how web content is served, cached or interpreted.

DCP-Portal has been reported to be vulnerable to an HTTP response
splitting attack via the PHPSESSID parameter when passed to the
calendar.php script. However, Nessus has not checked for this issue.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/52");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2016 k-otik.com & Copyright (C) 2004-2014 David Maciejak");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: avoid false-posiives caused by not checking for the app itself.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/calendar.php?year=2004&month=<script>foo</script>&day=01");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 if( "<script>foo</script>" >< buf )
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
