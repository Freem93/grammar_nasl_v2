#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11741);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2003-0495");
 script_bugtraq_id(7920);
 script_osvdb_id(2154);

 script_name(english:"LedNews News Post XSS");
 script_summary(english:"Checks for the presence of LedNews");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server is running LedNews, a set of scripts designed to
help maintain a news-based website.

There is a flaw in some versions of LedNews that could allow an
attacker to include rogue HTML code in the news, which may in turn be
used to steal the cookies of people visiting this site, or to annoy
them by showing pop-up error messages and such.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q2/107");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");    
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

function check(loc)
{
 local_var	r;
 r = http_send_recv3(method: "GET", item: strcat(loc, "/"), port:port);
 if (isnull(r)) exit(0);
 if ("<!-- Powered By LedNews: http://www.ledscripts.com -->" >< r[2])
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs()) check(loc:dir);
