
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47746);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_bugtraq_id(41548);
  script_osvdb_id(66242);
  script_xref(name:"Secunia", value:"40569");

  script_name(english:"FireStats window-add-excluded-ip.php 'edit' parameter XSS");
  script_summary(english:"Attempts to exploit a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FireStats installed on the remote host fails to
properly sanitize user-supplied input to the 'edit' parameter of the
'window-add-excluded-ip.php' script.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary script code in a user's browser.

Note that this version of FireStats is likely affected by cross-site
scripting issues in multiple other scripts; however, Nessus has not
tested for these.");
   # http://web.archive.org/web/20100712144211/http://h.ackack.net/more-0day-wordpress-security-leaks-in-firestats.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caf07989");
  script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/41548.txt");
  script_set_attribute(attribute:"see_also", value:"http://firestats.cc/changeset/2191");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:edgewall:firestats");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("firestats_detect.nasl", "wordpress_detect.nasl");
  script_require_keys("installed_sw/FireStats", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "FireStats";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Convert the scriptname to Unicode s we can use String.fromCharCode
payload = SCRIPT_NAME+'-'+unixtime();
enc_payload = '';
for(i=0; i<strlen(payload); i++)
{
  enc_payload += ord(payload[i]) + ',';
}
# Trim the trailing ',' character
enc_payload = substr(enc_payload, 0, strlen(enc_payload) - 2);
xss = '<script>alert(String.fromCharCode('+enc_payload+'))</script>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/php/window-add-excluded-ip.php',
  qs:'edit='+urlencode(str:xss),
  pass_str:'ID '+xss,
  ctrl_re:'Unknown ID'
);
if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
