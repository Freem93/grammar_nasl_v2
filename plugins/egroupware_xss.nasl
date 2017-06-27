#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14358);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2004-1467");
 script_bugtraq_id(11013);
 script_xref(name:"OSVDB", value:"9134");
 script_xref(name:"OSVDB", value:"9136");
 script_xref(name:"OSVDB", value:"9137");
 script_xref(name:"OSVDB", value:"9138");
 
 script_name(english:"eGroupWare <= 1.0.00.003 Multiple Module XSS");
 script_summary(english:"Checks for the presence of an XSS bug in EGroupWare");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of eGroupware is vulnerable to a cross-site
scripting attack.  This could allow a remote attacker to steal the
cookies of a legitimate user by tricking them into clicking a
maliciously crafted URL.

eGroupware reportedly has other cross-site scripting vulnerabilities,
though Nessus has not tested for those issues." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Aug/306"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to eGroupware 1.0.0.004 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/21");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("egroupware_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

kb  = get_kb_item("www/" + port + "/egroupware");
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb);
loc = stuff[2];

test_cgi_xss(port: port, dirs: make_list(loc), cgi: "/index.php",
 qs: "menuaction=calendar.uicalendar.day&date=20040405<script>foo</script>",
 pass_str: '<script>foo</script>');

