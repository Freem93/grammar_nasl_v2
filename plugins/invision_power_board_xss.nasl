#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12101);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2004-2279");
 script_bugtraq_id(9822);
 script_osvdb_id(18505);
 
 script_name(english:"Invision Power Board index.php pop Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"There is a bug in the version of Invision Power Board on the remote
host that makes it vulnerable to cross-site scripting attacks.  An
attacker may exploit this issue to steal the credentials of legitimate
users of this site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/356742" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/09");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

 script_summary(english:"Checks for the presence of an XSS bug in Invision PowerBoard");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("cross_site_scripting.nasl", "invision_power_board_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/invision_power_board");
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


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
    dir = matches[2];

    w = http_send_recv3(item:string(dir, "/index.php?s=&act=chat&pop=1;<script>foo</script>"), method:"GET", port:port);
    if (isnull(w)) exit(1, "The web server did not answer");
    r = w[2];

    if("<script>foo</script>" >< r)
    {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
}
