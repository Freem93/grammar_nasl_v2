#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66411);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2013-2549",
    "CVE-2013-2550",
    "CVE-2013-2718",
    "CVE-2013-2719",
    "CVE-2013-2720",
    "CVE-2013-2721",
    "CVE-2013-2722",
    "CVE-2013-2723",
    "CVE-2013-2724",
    "CVE-2013-2725",
    "CVE-2013-2726",
    "CVE-2013-2727",
    "CVE-2013-2729",
    "CVE-2013-2730",
    "CVE-2013-2731",
    "CVE-2013-2732",
    "CVE-2013-2733",
    "CVE-2013-2734",
    "CVE-2013-2735",
    "CVE-2013-2736",
    "CVE-2013-2737",
    "CVE-2013-3337",
    "CVE-2013-3338",
    "CVE-2013-3339",
    "CVE-2013-3340",
    "CVE-2013-3341",
    "CVE-2013-3342",
    "CVE-2013-3346"
  );
  script_bugtraq_id(
    58398,
    58568,
    59902,
    59903,
    59904,
    59905,
    59906,
    59907,
    59908,
    59909,
    59910,
    59911,
    59912,
    59913,
    59914,
    59915,
    59916,
    59917,
    59918,
    59919,
    59920,
    59921,
    59923,
    59925,
    59926,
    59927,
    59930,
    62149
  );
  script_osvdb_id(
    91201,
    91202,
    93335,
    93336,
    93337,
    93338,
    93339,
    93340,
    93341,
    93342,
    93343,
    93344,
    93345,
    93346,
    93347,
    93348,
    93349,
    93350,
    93351,
    93352,
    93353,
    93354,
    93355,
    93356,
    93357,
    93358,
    93359,
    96745
  );
  script_xref(name:"EDB-ID", value:"26703");
  script_xref(name:"ZDI", value:"ZDI-13-105");
  script_xref(name:"ZDI", value:"ZDI-13-106");
  script_xref(name:"ZDI", value:"ZDI-13-212");

  script_name(english:"Adobe Reader < 11.0.3 / 10.1.7 / 9.5.5 Multiple Vulnerabilities (APSB13-15) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 11.0.3, 10.1.7, or 9.5.5. It is, therefore, affected by the
following vulnerabilities :

  - Unspecified memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2013-2718,
    CVE-2013-2719, CVE-2013-2720, CVE-2013-2721,
    CVE-2013-2722, CVE-2013-2723, CVE-2013-2725,
    CVE-2013-2726, CVE-2013-2731, CVE-2013-2732,
    CVE-2013-2734, CVE-2013-2735, CVE-2013-2736,
    CVE-2013-3337, CVE-2013-3338, CVE-2013-3339,
    CVE-2013-3340, CVE-2013-3341, CVE-2013-3346)

  - An integer underflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2013-2549)

  - A use-after-free error exists that allows an attacker to
    bypass the Adobe Reader's sandbox protection.
    (CVE-2013-2550)

  - A flaw exists in the JavaScript API that allows an
    attacker to obtain sensitive information.
    (CVE-2013-2737)

  - An unspecified stack overflow condition exists that
    allows an attacker to execute arbitrary code.
    (CVE-2013-2724)

  - Multiple unspecified buffer overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-2730, CVE-2013-2733)

  - Multiple unspecified integer overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-2727, CVE-2013-2729)

  - A flaw exists due to improper handling of operating
    system domain blacklists. An attacker can exploit this
    to have an unspecified impact. (CVE-2013-3342)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-105/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-106/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-212/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.3 / 10.1.7 / 9.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader ToolButton Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (!get_kb_item("Host/MacOSX/Version"))
  audit(AUDIT_OS_NOT, "Mac OS X");

app = "Adobe Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 9 && ver[1] < 5) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 5)
)
  fix = "9.5.5";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 7)
)
  fix = "10.1.7";
else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 3)
  fix = "11.0.3";
else
  fix = "";

if (fix)
{
  info =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:info, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
