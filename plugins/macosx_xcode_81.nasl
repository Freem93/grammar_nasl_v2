#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94935);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2015-6764",
    "CVE-2015-8027",
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-1669",
    "CVE-2016-2086",
    "CVE-2016-2216"
  );
  script_bugtraq_id(
    78207,
    78209,
    78623,
    83141,
    83282,
    83754,
    83763,
    90584
  );
  script_osvdb_id(
    130244,
    130682,
    131037,
    131038,
    134454,
    134455,
    135121,
    135150,
    135151,
    137788
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-27-1");

  script_name(english:"Apple Xcode < 8.1 Node.js Multiple RCE (macOS)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"An IDE application installed on the remote macOS or Mac OS X host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote macOS or Mac OS X
host is prior to 8.1. It is, therefore, affected by multiple remote
code execution vulnerabilities in the Node.js component of the Xcode
Server. An unauthenticated, remote attacker can exploit these
vulnerabilities to cause a denial of service condition or the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207268");
  # http://lists.apple.com/archives/security-announce/2016/Oct/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0f77052");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item_or_exit("Host/MacOSX/Version");

# Patch is only available for OS X 10.11.5, 10.12 and later
if (ereg(pattern:"Mac OS X 10\.(([0-9]|10)(\.|$)|11(\.[0-4])?$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.11.5 or above");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '8.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  report_items = make_array(
    "Path", path,
    "Installed version", ver,
    "Fixed version", fix
  );
  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
