#
# (C) Tenable Network Security, Inc.
#

# From: <ersatz@unixhideout.com>
# To: bugtraq@securityfocus.com
# Subject: XSS vulnerabilites in Pafiledb



include("compat.inc");

if (description)
{
 script_id(11479);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2002-1931", "CVE-2005-0952");
 script_bugtraq_id(6021);
 script_xref(name:"OSVDB", value:"15809");
 
 script_name(english:"paFileDB pafiledb.php id Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by cross-
site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The version of paFileDB installed on the remote host is vulnerable to
cross-site scripting attacks due to its failure to sanitize input to
the 'id' parameter of the 'pafiledb.php' script before using it to
generate dynamic HTML.  An attacker may use these flaws to steal
cookies of users of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/310" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to paFileDB 3.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/20");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if pafiledb is vulnerable to XSS");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("pafiledb_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/pafiledb");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 test_cgi_xss(port: port, dirs: make_list(d), cgi: '/pafiledb.php',
 qs: 'action=download&id=4?"<script>alert(foo)</script>"',
 pass_str: "<script>alert(foo)</script>");
}
