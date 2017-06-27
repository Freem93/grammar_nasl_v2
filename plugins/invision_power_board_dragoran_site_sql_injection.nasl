#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20835);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-0520");
  script_bugtraq_id(16447);
  script_osvdb_id(22851);

  script_name(english:"Invision Power Board Dragoran Portal Module index.php site Parameter SQL Injection");
  script_summary(english:"Checks for site parameter SQL injection vulnerability in Invision Power Board Dragoran Portal Plugin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The installation of Invision Power Board on the remote host contains
an optional plugin module known as Dragoran Portal that fails to
sanitize input to the 'site' parameter of the 'index.php' script
before using it in database queries.  An attacker may be able to
leverage this issue to disclose sensitive information, modify data, or
launch attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/01");
 script_cvs_date("$Date: 2012/07/20 18:49:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  magic = string(rand() % 100, " UNION SELECT ", rand() % 100);
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "act=portal&",
      "site=", urlencode(str:magic)
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if we see a syntax error.
  if (egrep(pattern:string("mySQL query error: SELECT .+portal_sites +WHERE id=", magic), string:res)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
