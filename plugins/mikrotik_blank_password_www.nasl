#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39420);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(99335);

  script_name(english:"MikroTik RouterOS with Blank Password (HTTP)");
  script_summary(english:"Tries to log in as admin");

  script_set_attribute(attribute:"synopsis", value:"The remote router has no password for its admin account.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MikroTik RouterOS without a password for its
'admin' account.  Anyone can connect to it and gain administrative
access to it.");
  script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/documentation.html");
  script_set_attribute(attribute:"solution", value:
"Log in to the device and configure a password using the '/password'
command.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "admin"; pass = "";


page = http_get_cache(port: port, item: "/", exit_on_fail: TRUE);

# Old version
if (
  '<input type="text" name="user"' >< page &&
  '<input type="password" name="password">' >< page &&
  '<input type="submit" name="" value="Connect">' >< page
)
{
  clear_cookiejar();
  # Need to set a cookie
  r = http_send_recv3(port: port, item:"/", method: "GET", follow_redirect: 2, exit_on_fail: TRUE);

  d = strcat("process=login&page=start&user=", user, "&password=", pass, "&=Connect");

  r = http_send_recv3(method: "POST", item: "/main.html", port: port,
    content_type: "application/x-www-form-urlencoded",
    data: d, exit_on_fail: TRUE);

  if (
    r[0] =~ "^HTTP/1\.[01] 200 " &&
    '<form name="deviceForm" action="/main.html"' >< r[2] &&
    '<form name="networksForm" action="/main.html"' >< r[2]
  )
  {
    security_hole(port);
    exit(0);
  }
}

# Mikrotik RouterOS 3.30, 4.11, 5.0beta6
if (
  '<form name="loginForm" action="/cfg" method="post" onsubmit="' >< page &&
  '<input type="hidden" name="process" value="login"/>' >< page
)
{
  # Need to set a cookie
  r = http_send_recv3(port: port, item:"/cfg", method: "GET", follow_redirect: 2, exit_on_fail: TRUE);

  d = strcat("process=login&page=start&backpage=%2F&user=", user, "&password=&=Login");
  r = http_send_recv3(method: "POST", item: "/cfg", port: port,
    content_type: "application/x-www-form-urlencoded",
    data: d, exit_on_fail: TRUE, version: 11);

  if (
    r[0] =~ "^HTTP/1\.[01] 200 " &&
    '<h3>invalid user name or password' >!< r[2] &&
    '<script language="JavaScript">' >< r[2] &&
    'function change() {self.location="/cfg?page=interface"}' >< r[2]
  )
  {
    security_hole(port);
    exit(0);
  }
}

audit(AUDIT_HOST_NOT, "affected");
