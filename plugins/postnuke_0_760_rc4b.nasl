#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19545);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2689", "CVE-2005-2690");
  script_bugtraq_id(14635, 14636);
  script_osvdb_id(18970, 18971, 18972);

  script_name(english:"PostNuke <= 0.760 RC4b Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to several
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PostNuke version 0.760 RC4b or
older.  These versions suffer from several vulnerabilities :

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary HTML and script 
    code into the browser of users by manipulating
    input to the 'moderate' parameter of the 
    'Comments' module and the 'htmltext' parameter
    of the 'user.php' script.

  - A SQL Injection Vulnerability
    The application fails to launder user-supplied
    input to the 'show' parameter in the
    'modules/Downloads/dl-viewdownload.php' module.
    With admin rights, an attacker could exploit 
    this issue to manipulate SQL queries." );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/22" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/286" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PostNuke version 0.760 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/22");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
script_end_attributes();


  script_summary(english:"Detects multiple vulnerabilities in PostNuke <= 0.760 RC4b");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

exploits = make_list(
  string(
    "/index.php?",
    "module=Comments&",
    "req=moderate&",
    "moderate=<center><h1>", exss
  ),
  string(
    "/user.php?",
    "op=edituser&",
    "htmltext=<h1>", exss
  )
);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # It's a problem if we see our XSS.
    if (xss >< res) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
