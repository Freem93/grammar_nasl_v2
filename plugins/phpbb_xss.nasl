#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12093);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");

 script_cve_id("CVE-2004-1809");
 script_bugtraq_id(9865, 9866);
 script_osvdb_id(4257, 4259);
 
 script_name(english:"phpBB < 2.0.7 Multiple XSS");
 script_summary(english:"XSS test");
 
 script_set_attribute(attribute:"synopsis", value:"A remote CGI is vulnerable to cross-site scripting.");
 script_set_attribute(attribute:"description", value:
"There are cross-site scripting vulnerabilities in the files
'ViewTopic.php' and 'ViewForum.php' in the remote installation of
phpBB.");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 2.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencies("phpbb_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
dir = matches[2];

r = http_send_recv3(method: "GET", item:dir + "/viewtopic.php?t=10&postdays=99<script>foo</script>", port:port);
if (isnull(r)) exit(0);

r2 = http_send_recv3(method: "GET", item:dir + "/viewforum.php?f=10&postdays=99<script>foo</script>", port:port);
if (isnull(r2)) exit(0);

if("<script>foo</script>" >< r[2] || "<script>foo</script>" >< r2[2])
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
