#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(13843);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2004-0725");
  script_bugtraq_id(10718);
  script_osvdb_id(7865);
  script_xref(name:"Secunia", value:"12065");

  script_name(english:"Moodle < 1.3.3 'help.php' 'file' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle running on the remote host is affected by a
cross-site scripting vulnerability. Input to the 'file' parameter of
'help.php' is not properly sanitized. A remote attacker can exploit
this by tricking a user into requesting a maliciously crafted URL,
resulting in stolen credentials.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/128");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle 1.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencie("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

url = dir + "/help.php?file=<script>foo</script>";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if ("Help file '<script>x</script>' could not be found!" >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
