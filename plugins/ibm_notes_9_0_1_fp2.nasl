#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77812);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0446",
    "CVE-2014-0448",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0963",
    "CVE-2014-1876",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66879,
    66881,
    66883,
    66887,
    66891,
    66894,
    66898,
    66899,
    66902,
    66903,
    66904,
    66905,
    66907,
    66909,
    66910,
    66911,
    66914,
    66915,
    66916,
    66919,
    66920,
    67238
  );
  script_osvdb_id(
    99711,
    101309,
    102808,
    105866,
    105867,
    105869,
    105873,
    105874,
    105875,
    105876,
    105877,
    105878,
    105879,
    105880,
    105881,
    105882,
    105883,
    105884,
    105885,
    105886,
    105887,
    105889,
    105890,
    105892,
    105895,
    105897,
    105898,
    105899,
    106786
  );

  script_name(english:"IBM Notes 9.0.x < 9.0.1 Fix Pack 2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM Notes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Notes (formerly Lotus Notes)
9.0.x prior to 9.0.1 Fix Pack 2 (FP2) installed. It is, therefore,
affected by the following vulnerabilities :

  - An unspecified error exists related to the TLS
    implementation and the IBM HTTP server that could allow
    certain error cases to cause 100% CPU utilization. Note
    this issue only affects Microsoft Windows hosts.
    (CVE-2014-0963)

  - Fixes in the Oracle Java CPU for April 2014 are included
    in the fixed IBM Java release, which is included in the
    fixed IBM Domino release.
    (CVE-2013-6629, CVE-2013-6954, CVE-2014-0429,
    CVE-2014-0446, CVE-2014-0448, CVE-2014-0449,
    CVE-2014-0451, CVE-2014-0452, CVE-2014-0453,
    CVE-2014-0454, CVE-2014-0455, CVE-2014-0457,
    CVE-2014-0458, CVE-2014-0459, CVE-2014-0460,
    CVE-2014-0461, CVE-2014-1876, CVE-2014-2398,
    CVE-2014-2401, CVE-2014-2402, CVE-2014-2409,
    CVE-2014-2412, CVE-2014-2414, CVE-2014-2420,
    CVE-2014-2421, CVE-2014-2423, CVE-2014-2427,
    CVE-2014-2428)");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21681114");
  # 9.0.1 Fix Pack 2 downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037141");
  # PSIRT blog post
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_ibm_notes_and_domino_multiple_vulnerabilities_in_ibm_java_oracle_april_2014_critical_patch_update_and_ibm_http_server_for_domino_cve_2014_0963?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25018df0");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Notes 9.0.1 FP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_notes_installed.nasl");
  script_require_keys("installed_sw/IBM Notes");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "IBM Notes";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

install = get_single_install(app_name:appname);

version = install['version'];
path = install['path'];
ver_ui = install['display_version'];

fix = '9.0.12.14215';

if (
  ver_ui =~ "^9\.0\.[01]($|[^0-9])" &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : 9.0.1 FP2 (' + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
