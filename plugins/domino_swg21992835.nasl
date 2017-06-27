#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95882);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/12 20:45:52 $");

  script_cve_id(
    "CVE-2016-0282",
    "CVE-2016-2938",
    "CVE-2016-2939",
    "CVE-2016-3092",
    "CVE-2016-5880",
    "CVE-2016-5881",
    "CVE-2016-5882",
    "CVE-2016-5884",
    "CVE-2016-6113"
  );
  script_bugtraq_id(
    91453,
    94558,
    94600,
    94602,
    94603,
    94604,
    94605,
    94606
  );
  script_osvdb_id(
    140354,
    145284,
    146622,
    146623,
    146624,
    146625,
    146626,
    146627,
    146628,
    149974
  );
  script_xref(name:"IAVB", value:"2016-B-0181");

  script_name(english:"IBM Domino 8.5.x < 8.5.3 Fix Pack 6 Interim Fix 15 / 9.0.x < 9.0.1 Fix Pack 7 Interim Fix 1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"A business collaboration application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM
Lotus Domino) running on the remote host is 8.5.x prior to 8.5.3 Fix
Pack 6 (FP6) Interim Fix 15 (IF15) or 9.0.x prior to 9.0.1 Fix Pack 7
(FP7) Interim Fix 1 (IF1). It is, therefore, affected by the following
vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the iNotes component due to improper validation
    of user-supplied input. An authenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-0282, CVE-2016-5880)
  
  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the iNotes component due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit these, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-2938, CVE-2016-2939,
    CVE-2016-5881, CVE-2016-5882, CVE-2016-6113,
    CVE-2016-5884)

  - A denial of service vulnerability exists in the Apache
    Commons FileUpload component due to improper handling of
    boundaries in content-type headers when handling file
    upload requests. An unauthenticated, remote attacker can
    exploit this to cause processes linked against the
    library to become unresponsive. (CVE-2016-3092)");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21992835");
  # 8.5.3 Patch
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21663874");
  # 9.0.1 Patch
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21657963");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 8.5.3 Fix Pack 6 (FP6) Interim Fix 15
(IF15) / 9.0.1 Fix Pack 7 (FP7) Interim Fix 1 (IF1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# IBM may provide custom hotfixes to customers, which we have no way
# to check for, so this plugin should be paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Ensure sufficient granularity
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Check for 8.5 / 8.5.0 / 8.5.1 / 8.5.2 / 8.5.3
if (ver =~ "^8\.5(($|[^0-9])|\.[0-3]($|[^0-9]))")
{
  fix = "8.5.3 FP6 IF15";
  fix_ver = "8.5.3";
  fix_pack = 6;
  hotfix = 2876;
}
# Check for 9.0 / 9.0.0 / 9.0.1
else if (ver =~ "^9\.0(($|[^0-9])|\.[0-1]($|[^0-9]))")
{
  fix = "9.0.1 FP7 IF1";
  fix_ver = "9.0.1";
  fix_pack = 7;
  hotfix = 92;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = eregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: HF(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 as a placeholder if no FP or HF. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);
if (!version[3]) version[3] = 0;
else version[3] = int(version[3]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] < fix_pack) ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] == fix_pack && version[3] < hotfix)
)
{
  security_report_v4(
    xss:TRUE,
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
