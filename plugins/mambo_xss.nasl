#
# This script was completely rewritten by Tenable Network Security, using a new API
#
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <ertank@olympos.org> 
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns </archive/1/315554/2003-03-19/2003-03-25/1>
#


include("compat.inc");

if (description)
{
 script_id(11441);
 script_cve_id("CVE-2003-1203");
 script_bugtraq_id(7135);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"7493");
 script_version ("$Revision: 1.23 $");

 script_name(english:"Mambo Site Server 4.0.10 XSS");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"An attacker may use the installed version of Mambo Site Server to
perform a cross-site scripting attack on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/315554" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/18");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/mambo_mos");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 test_cgi_xss(port: port, cgi: "/index.php", dirs: make_list(dir), 
  qs: "option=search&searchword=<script>alert(document.cookie);</script>",
  pass_str: "<script>alert(document.cookie);</script>");
}
