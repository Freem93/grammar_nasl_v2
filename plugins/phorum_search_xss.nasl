#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(14185);
 script_version ("$Revision: 1.17 $"); 

 script_cve_id("CVE-2004-2242");
 script_bugtraq_id(10822);
 script_osvdb_id(38022);

 script_name(english:"Phorum search.php subject Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a cross-
site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of Phorum contains a script called 'search.php'
that is vulnerable to a cross-site scripting attack.  An attacker may
be able to exploit this problem to steal the authentication
credentials of third-party users." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2004/Jul/1010787.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phorum.org/cvs-changelog-5.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 5.0.7a.beta or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/27");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phorum:phorum");
 script_end_attributes();

 script_summary(english:"Checks for the presence of an XSS bug in Phorum");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("phorum_detect.nasl", "cross_site_scripting.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 w = http_send_recv3(method:"GET",item:string(loc, "/search.php?12,search=vamp,page=1,match_type=ALL,match_dates=00,match_forum=ALL ,body=,author=,subject=<script>foo</script>"), port:port);
 if (isnull(w)) exit(0);
 r = w[2];
 if("<script>foo</script>" >< r)
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
