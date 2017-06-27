#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80486);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2015-0301",
    "CVE-2015-0302",
    "CVE-2015-0303",
    "CVE-2015-0304",
    "CVE-2015-0305",
    "CVE-2015-0306",
    "CVE-2015-0307",
    "CVE-2015-0308",
    "CVE-2015-0309"
  );
  script_bugtraq_id(
    72031,
    72032,
    72033,
    72034,
    72035,
    72036,
    72037,
    72038,
    72039
  );
  script_osvdb_id(
    116944,
    116945,
    116946,
    116947,
    116948,
    116949,
    116950,
    116951,
    116952
  );

  script_name(english:"Adobe AIR for Mac <= 15.0.0.356 Multiple Vulnerabilities (APSB15-01)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Adobe AIR installed on the remote Mac OS
X host is equal or prior to 15.0.0.356. It is, therefore, affected by
the following vulnerabilities :

  - An unspecified improper file validation issue.
    (CVE-2015-0301)

  - An unspecified information disclosure vulnerability,
    which can be exploited to capture keystrokes.
    (CVE-2015-0302)

  - Multiple memory corruption vulnerabilities allow an
    attacker to execute arbitrary code. (CVE-2015-0303,
    CVE-2015-0306)

  - Multiple heap-based buffer overflow vulnerabilities
    that can be exploited to execute arbitrary code.
    (CVE-2015-0304, CVE-2015-0309)

  - An unspecified type confusion vulnerability that can
    lead to code execution. (CVE-2015-0305)

  - An out-of-bounds read vulnerability that can be
    exploited to leak memory addresses. (CVE-2015-0307)

  - A use-after-free vulnerability that results in arbitrary
    code execution. (CVE-2015-0308)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-01.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 16.0.0.245 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '15.0.0.356';
fixed_version_for_report = '16.0.0.245';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
