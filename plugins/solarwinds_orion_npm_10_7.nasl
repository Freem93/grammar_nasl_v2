#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73963);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/27 13:33:27 $");

  script_cve_id("CVE-2014-3459");
  script_bugtraq_id(66741, 67048);
  script_osvdb_id(105643, 105644, 105645, 105646, 105647, 106249);

  script_name(english:"SolarWinds Orion NPM < 10.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of SolarWinds Orion NPM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of SolarWinds Orion NPM prior to
version 10.7. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists in the 'wpdlx' ActiveX control where the
    application fails to validate file types when loading or
    saving images. This can allow a context-dependent
    attacker to execute arbitrary code. (ZDI-14-064)

  - A flaw exists in the 'C1Chart3D8' ActiveX control when
    handling an OC3 file with the LoadURL method. This can
    allow a context-dependent attacker to execute arbitrary
    code. (ZDI-14-065)

  - A stack-based buffer overflow flaw exists in the 'Apex'
    ActiveX control where user input is not validated. This
    can allow a context-dependent attacker to cause a denial
    of service or execute arbitrary code. (ZDI-14-066)

  - A flaw exists in the 'VSReport' ActiveX control that
    can allow a remote attacker to execute arbitrary code.
    (ZDI-14-067)

  - A path traversal flaw exists in the 'FSMWebService'
    where the 'DownloadFileServlet' does not properly
    sanitize user input. This can allow a remote attacker,
    using a specially crafted request, to access arbitrary
    files. (ZDI-14-068)

  - A heap buffer overflow flaw exists due to user supplied
    input not being validated when handling the 'PEstrarg1'
    property. This can allow a context-dependent attacker
    to cause a denial of service or execute arbitrary code.
    (ZDI-14-115)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-064/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-065/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-066/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-067/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-115/");
  # http://www.solarwinds.com/documentation/Orion/docs/ReleaseNotes/releaseNotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea627d5d");
  script_set_attribute(attribute:"solution", value:"Upgrade to SolarWinds Orion NPM 10.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_performance_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8787);
  script_dependencies("solarwinds_orion_npm_detect.nasl");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8787);

app = "SolarWinds Orion Core";

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(
  app_name  : app,
  port      : port
);

appname = "SolarWinds Orion Network Performance Monitor";

dir = install['path'];
install_loc = build_url(port:port, qs:dir+"/Login.aspx");

version = install['NPM Version'];

if (isnull(version)) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_loc);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 10.7 are vulnerable
if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 7)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 10.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc, version);
