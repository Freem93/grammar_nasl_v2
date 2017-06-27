#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17608);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-0885", "CVE-2005-2574", "CVE-2005-2575");
  script_bugtraq_id(12886, 14523);
  script_osvdb_id(14993, 18659, 18660);

  script_name(english:"XMB Forum < 1.9.10 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in XMB Forum < 1.9.10");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote web server hosts a PHP application that is affected by
multiple issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running XMB Forum, a web forum written in PHP. 

According to its banner, the version of XMB installed on the remote
host suffers from cross-site scripting, SQL injection, and input
validation vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2005/Aug/132"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://http://forums.xmbforum.com/viewthread.php?tid=773046"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://forums.xmbforum.com/viewthread.php?tid=764607" 
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to XMB 1.9.10 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/22");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Check various directories for XMB.
if (thorough_tests) dirs = list_uniq(make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Look for the version number in the login script.
  r = http_send_recv3(method: "GET", item:string(dir, "/misc.php?action=login"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  # To actually exploit the vulnerabilities reliably, you need
  # to be logged in so the best we can do is a banner check.
  if (
    # Sample banners:
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.05</font><br />
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.5 RC4: Summer Forest<br />
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 Magic Lantern Final<br></b>
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 v2b Magic Lantern Final<br></b>
    #   Powered by XMB 1.8 Partagium SP1<br />
    #   Powered by XMB 1.9 Nexus (beta)<br />
    #   Powered by XMB 1.9.1 RC1 Nexus<br />
    #   Powered by XMB 1.9.2 Nexus (pre-Alpha)<br />
    egrep(string:res, pattern:"Powered by .*XMB(<[^>]+>)* v?(0\.|1\.([0-8][^0-9]|9([^0-9]|\.[0-9][^0-9])))")
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
