#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17610);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-0870");
  script_bugtraq_id(12887);
  script_osvdb_id(14949, 14950);

  script_name(english:"PHPSysInfo < 2.5 Multiple Script XSS");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains two PHP scripts that are prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpSysInfo, a PHP script that parses the
/proc entries on Linux systems and displays them in HTML. 

The version of phpSysInfo installed on the remote host is affected by
multiple cross-site scripting vulnerabilities due to its failure to
sanitize user input to the 'sensor_program' parameter of 'index.php'
and the 'text[language]', 'text[template]', and 'VERSION' parameters
of 'system_footer.php'.  If PHP's 'register_globals' setting is
enabled, a remote attacker can exploit these flaws to have arbitrary
script rendered in the browser of a user in the context of the
affected website." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/394086" );
  # http://sourceforge.net/project/shownotes.php?release_id=376350&group_id=15
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc6ee430" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpSysInfo 2.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/23");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpsysinfo:phpsysinfo");
script_end_attributes();


  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPSysInfo");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);


# Loop through various directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the XSS flaws.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/index.php?",
      "sensor_program=", exss
    ));
  if (isnull(r)) exit(0);
  res = r[2];


  # There's a problem if we see our XSS.
  if (string("Error: ", xss, " is not currently supported") >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
