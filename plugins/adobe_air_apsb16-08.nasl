#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89868);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2016-0960",
    "CVE-2016-0961",
    "CVE-2016-0962",
    "CVE-2016-0963",
    "CVE-2016-0986",
    "CVE-2016-0987",
    "CVE-2016-0988",
    "CVE-2016-0989",
    "CVE-2016-0990",
    "CVE-2016-0991",
    "CVE-2016-0992",
    "CVE-2016-0993",
    "CVE-2016-0994",
    "CVE-2016-0995",
    "CVE-2016-0996",
    "CVE-2016-0997",
    "CVE-2016-0998",
    "CVE-2016-0999",
    "CVE-2016-1000",
    "CVE-2016-1001",
    "CVE-2016-1002",
    "CVE-2016-1005",
    "CVE-2016-1010"
  );
  script_bugtraq_id(
    84308,
    84308,
    84310,
    84311,
    84312
  );
  script_osvdb_id(
    135679,
    135680,
    135681,
    135682,
    135683,
    135684,
    135685,
    135686,
    135687,
    135688,
    135689,
    135690,
    135691,
    135692,
    135693,
    135694,
    135695,
    135696,
    135697,
    135698,
    135699,
    135700,
    135701
);

  script_name(english:"Adobe AIR <= 20.0.0.260 Multiple Vulnerabilities (APSB16-08)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Windows host is prior
or equal to version 20.0.0.260. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0963,
    CVE-2016-0993, CVE-2016-1010)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0987,
    CVE-2016-0988, CVE-2016-0990, CVE-2016-0991,
    CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
    CVE-2016-0997, CVE-2016-0998, CVE-2016-0999,
    CVE-2016-1000)

  - A heap overflow condition exists that allows an attacker
    to execute arbitrary code. (CVE-2016-1001)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0960,
    CVE-2016-0961, CVE-2016-0962, CVE-2016-0986,
    CVE-2016-0989, CVE-2016-0992, CVE-2016-1002,
    CVE-2016-1005)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 21.0.0.176 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '20.0.0.260';
fix = '21.0.0.176';
fix_ui = '21.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' +
      '\n';
    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
