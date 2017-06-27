#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11760);
 script_version ("$Revision: 1.27 $");
 script_bugtraq_id(7933, 7936);
 script_xref(name:"OSVDB", value:"54731");
 script_xref(name:"OSVDB", value:"54732");
 
 script_name(english:"pod.board 1.1 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host is hosting the Pod.Board CGI suite, a set of PHP scripts
designed to manage online forums.

There is a cross-site scripting issue in this suite that could allow an
attacker to steal the cookies of your legitimate users, by luring them
into clicking on a rogue URL." );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for Pod.Board XSS");
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/forum_details.php", 
 qs: "user_nick=<script>foo</script>", pass_str: "<script>foo</script>");
