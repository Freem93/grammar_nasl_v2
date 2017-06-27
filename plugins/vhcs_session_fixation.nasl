#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25990);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3988");
  script_bugtraq_id(25006);
  script_osvdb_id(39368);

  script_name(english:"VHCS PHPSESSID Cookie Session Fixation");
  script_summary(english:"Tries to use a fixed arbitrary session identifier");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
session fixation issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running VHCS, a control panel for hosting
providers. 

The GUI portion of the version of VHCS installed on the remote host
accepts session identifiers from GET (and likely POST) variables,
which makes it susceptible to a session fixation attack.  An attacker
may be able to exploit this issue to gain access to the affected
application using a known session identifier if he can trick a user
into logging in, say, via a specially crafted link." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/231");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/05");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
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


port = get_http_port(default:80, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq("/vhcs2", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  url = string(dir, "/index.php");
  # Grab index.php.
  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  # Make sure it's VHCS and that a session cookie is being set.
  if (
    ">VHCS - Virtual Hosting Control System<" >< res &&
    'action="chk_login.php" method="post"' >< res &&
    egrep(pattern:"^Set-Cookie2?:.+PHPSESSID=", string:res)
  )
  {
    # Try to exploit the flaw.
    erase_http_cookie(name: "PHPSESSID");
    r = http_send_recv3(method: "GET", 
      item:string(url, "?PHPSESSID=bc2e59c52cd7a9ae8978014e2110f203"), 
      exit_on_fail: 1,
      port:port
    );

    # There's a problem if the app doesn't create another session cookie.
    if (
      ">VHCS - Virtual Hosting Control System<" >< r[2] &&
      'action="chk_login.php" method="post"' >< r[2] &&
      !egrep(pattern:"^Set-Cookie2?:.+PHPSESSID=", string:r[1])
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
