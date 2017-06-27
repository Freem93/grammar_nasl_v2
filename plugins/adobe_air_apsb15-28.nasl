#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86850);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id(
    "CVE-2015-7651",
    "CVE-2015-7652",
    "CVE-2015-7653",
    "CVE-2015-7654",
    "CVE-2015-7655",
    "CVE-2015-7656",
    "CVE-2015-7657",
    "CVE-2015-7658",
    "CVE-2015-7659",
    "CVE-2015-7660",
    "CVE-2015-7661",
    "CVE-2015-7662",
    "CVE-2015-7663",
    "CVE-2015-8042",
    "CVE-2015-8043",
    "CVE-2015-8044",
    "CVE-2015-8046"
  );
  script_osvdb_id(
    129999,
    130000,
    130001,
    130002,
    130003,
    130004,
    130005,
    130006,
    130007,
    130008,
    130009,
    130010,
    130011,
    130012,
    130013,
    130014,
    130015
  );

  script_name(english:"Adobe AIR <= 19.0.0.213 Multiple Vulnerabilities (APSB15-28)");
  script_summary(english:"Checks the version of AIR.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Windows host is equal
or prior to version 19.0.0.241. It is, therefore, affected by multiple
vulnerabilities :

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-7659)

  - A security bypass vulnerability exists that allows an
    attacker to write arbitrary data to the file system
    under user permissions. (CVE-2015-7662)

  - Multiple use-after-free vulnerabilities exist that allow
    an attacker to execute arbitrary code. (CVE-2015-7651,
    CVE-2015-7652, CVE-2015-7653, CVE-2015-7654,
    CVE-2015-7655, CVE-2015-7656, CVE-2015-7657,
    CVE-2015-7658, CVE-2015-7660, CVE-2015-7661,
    CVE-2015-7663, CVE-2015-8042, CVE-2015-8043,
    CVE-2015-8044, CVE-2015-8046)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 19.0.0.241 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

cutoff_version = '19.0.0.213';
fix = '19.0.0.241';
fix_ui = '19.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
