#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66807);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/24 02:20:54 $");

  script_bugtraq_id(44731);
  script_osvdb_id(69137);

  script_name(english:"SAP Control SOAP Web Service Remote Code Execution (SAP Note 1414444)");
  script_summary(english:"Checks the version of SAP Control");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a SOAP service that can be abused to
execute arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Control, offered by 'sapstartsrv.exe', reportedly
contains an arbitrary remote code execution vulnerability.  A malformed
SOAP request (via POST) can be used to reach an unbounded copy loop,
which results in attacker-supplied data being written into existing
function pointers.  A remote, unauthenticated attacker could use this to
execute code that, by default, runs as SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-236/");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1414444");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("sap_control_detect.nasl");
  script_require_keys("www/sap_control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "SAP Control";

port = get_http_port(default:50013, embedded:TRUE);
install = get_install_from_kb(appname:"sap_control", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

matches = eregmatch(string:ver, pattern:"^(\d+), patch (\d+),");
if (isnull(matches)) exit(1, "Failed to parse the version '" + ver + "' of "+app+" on port " + port + ".");
release = int(matches[1]);
patch = int(matches[2]);

# SAP Note 1414444 gives the following list of patches.
patches = make_array(
  640, 313,
  700, 236,
  701, 73,
  710, 181,
  711, 67,
  720, 29
);

fix = patches[release];
if (isnull(fix) || patch >= fix) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + release + ', patch ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
