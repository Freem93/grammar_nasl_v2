#
# (C) Tenable Network Security, Inc.
#

#  Ref: Arab VieruZ <arabviersus@hotmail.com>
#



include("compat.inc");

if(description)
{
 script_id(14833);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2004-1824");
 script_bugtraq_id(6226);
 script_osvdb_id(3280);
  
 script_name(english:"vBulletin memberlist.php what Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of vBulletin is vulnerable to a cross-site
scripting issue due to a failure of the application to properly
sanitize user-supplied URI input.  As a result of this vulnerability,
it is possible for a remote attacker to create a malicious link
containing script code that will be executed in the browser of an
unsuspecting user when followed.  This may facilitate the theft of
cookie-based authentication credentials as well as other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Nov/298");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/11/21");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:jelsoft:vbulletin");
script_end_attributes();

 script_summary(english: "Checks memberlist.php XSS flaw in vBulletin");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl", "vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/vBulletin");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
  
# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/memberlist.php", 
 qs: "s=23c37cf1af5d2ad05f49361b0407ad9e&what=<script>foo</script>",
 pass_str: "<script>foo</script>" );
}
