#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18573);
  script_version("$Revision: 1.20 $");

  script_cve_id(
    "CVE-2005-1113", 
    "CVE-2005-1114", 
    "CVE-2005-1115", 
    "CVE-2005-1116"
 );
  script_bugtraq_id(
    13149, 
    13150, 
    13151, 
    13152, 
    13153
 );
  script_osvdb_id(
    15925, 
    15926, 
    15927, 
    15928, 
    15929, 
    15930,
    15931,
    15932,
    15933
 );

  script_name(english:"phpBB2 Plus <= 1.52 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
multiple cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB2 Plus that suffers from
multiple cross-site scripting flaws due to a general failure of the
application and associated modules to sanitize user-supplied input." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/191" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/13");
 script_cvs_date("$Date: 2017/02/23 16:41:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb_plus");
script_end_attributes();

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in phpBB Plus <= 1.52");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  # nb: phpbb_detect.nasl should identify installs of phpBB2 Plus
  #     since it's just a modified distribution of phpBB.
  script_dependencies("phpbb_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (!can_host_php(port:port)) exit(0);


# A simple alert to display the script name.
xss = "<script>JavaScript:alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3EJavaScript:alert('" + SCRIPT_NAME + "')%3B%3C%2Fscript%3E";


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/calendar_scheduler.php?",
      "d=", unixtime(), "&",
      "mode=&",
      "start=%22%3E", exss, "&",
      "sid=69bfdd7e0b7c9852d26077789afafa84"
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like phpBB2 Plus and...
    'Powered by <a href="http://www.phpbb2.de/" target="_phpbb">phpBB2 Plus' >< res &&
    # we see our exploit.
    xss >< res
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
