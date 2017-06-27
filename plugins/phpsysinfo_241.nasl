#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20215);
  script_version("$Revision: 1.19 $");

  script_cve_id(
    "CVE-2003-0536",
    "CVE-2005-0870",
    "CVE-2005-3347",
    "CVE-2005-3348"
 );
  script_bugtraq_id(7286, 15396, 15414);
  script_osvdb_id(8928, 14949, 14950, 20821, 21159);

  script_name(english:"phpSysInfo < 2.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpSysInfo < 2.4.1");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpSysInfo, a PHP application that parses
the /proc entries on Linux/Unix systems and displays them in HTML.

The installed version of phpSysInfo on the remote host has a design
flaw in its globalization layer such that the script's variables can
be overwritten independent of PHP's 'register_globals' setting.  By
exploiting this issue, an attacker may be able to read arbitrary files
on the remote host and even execute arbitrary PHP code, both subject
to the privileges of the web server user id.

In addition, the application fails to sanitize user-supplied input
before using it in dynamically-generated pages, which can be used to
conduct cross-site scripting and HTTP response splitting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_222005.81.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpSysInfo 2.4.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 352);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/16");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpsysinfo:phpsysinfo");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/18");
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpsysinfo", "/phpSysInfo", "/sysinfo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit some of the flaws.
  r = http_send_recv3(method: "GET", port: port,
    item:string(
      dir, "/index.php?",
      # if successful, output will have the footer repeated.
      "lng=../system_footer&",
      # if successful, output will complain about an invalid sensor program.
      "sensor_program=", SCRIPT_NAME));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we overwrote $sensor_program.
  if (string("<center><b>Error: ", SCRIPT_NAME, " is not currently supported</b></center>") >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }

  # Alternatively, there's a problem if it looks like phpSysInfo and...
  if ("phpSysInfo-" >< res || "Created By: phpSysInfo" >< res) {
    # there are two footers.
    footer = "</html>";
    post_footer = strstr(res, footer);
    if (post_footer) {
      post_footer = post_footer - footer;
      if (strstr(post_footer, footer)) {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
