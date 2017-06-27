#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91458);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/03 18:22:12 $");

  script_osvdb_id(138178);
  script_xref(name:"ZDI", value:"ZDI-14-428");

  script_name(english:"SolarWinds Server & Application Monitor (SAM) Alert Handling Local Privilege Escalation");
  script_summary(english:"Checks the version of SolarWinds Server & Application Monitor (SAM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Server & Application Monitor (SAM) running
on the remote host is affected by a privilege escalation vulnerability
in the Alert Manager component due to improper handling of specially
crafted alerts. A local attacker can exploit this to gain elevated
privileges and execute arbitrary code in the context of NT
Authority\SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-428/");
  script_set_attribute(attribute:"solution", value:
"No patch is currently available, and the vendor has no plans to
release a patch in the future.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:server_and_application_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_sam_detect.nbin");
  script_require_ports("Services/www", 8787);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");
include("misc_func.inc");

app = "SolarWinds Server & Application Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8787);

install = get_single_install(
    app_name: app,
    port: port,
    exit_if_unknown_ver: TRUE
);

version = install['version'];
dir = install['dir'];
url = build_url(qs:dir, port:port);

fix_ver = "6.2.3";  # misnomer : there is no fix version currently

# granularity check
# x.y.z
parts = split(version, sep:'.');
if (len(parts) < 3) audit(AUDIT_VER_NOT_GRANULAR, app, version);

# if ver <= 6.2.3, vuln
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) <= 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  No patch is currently available, and the vendor has no ' +
    'plans to release a patch in the future.';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
