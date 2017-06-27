#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15506);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2004-1599", "CVE-2004-1601");
 script_bugtraq_id(11437);
 script_xref(name:"OSVDB", value:"10899");
 script_xref(name:"OSVDB", value:"10901");

 script_name(english:"CoolPHP 1.0 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is vulnerable to
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the CoolPHP Content Management system.

There are various flaws in the remote version of this software which
may allow an attacker to read arbitrary files on the remote host or to
set up a cross-site scripting attack." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/16");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for CoolPHP");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

test_cgi_xss(port: port, cgi: '/index.php', 
 qs: "op=userinfo&nick=<script>foo</script>", 
 pass_str: "<script>foo</script>");
