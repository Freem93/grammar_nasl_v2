#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77578);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2014-0547",
    "CVE-2014-0548",
    "CVE-2014-0549",
    "CVE-2014-0550",
    "CVE-2014-0551",
    "CVE-2014-0552",
    "CVE-2014-0553",
    "CVE-2014-0554",
    "CVE-2014-0555",
    "CVE-2014-0556",
    "CVE-2014-0557",
    "CVE-2014-0559"
  );
    script_bugtraq_id(
    69695,
    69696,
    69697,
    69699,
    69700,
    69701,
    69702,
    69703,
    69704,
    69705,
    69706,
    69707
  );
  script_osvdb_id(
    111100,
    111101,
    111102,
    111103,
    111104,
    111105,
    111106,
    111107,
    111108,
    111109,
    111110,
    111111
  );

  script_name(english:"Adobe AIR for Mac <= 14.0.0.178 Multiple Vulnerabilities (APSB14-21)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Mac OS X host is equal or prior to 14.0.0.178. It is, therefore,
affected by the following vulnerabilities :

  - Unspecified memory corruption issues exist that allow
    arbitrary code execution. (CVE-2014-0547, CVE-2014-0549,
    CVE-2014-0550, CVE-2014-0551, CVE-2014-0552,
    CVE-2014-0555)

  - An unspecified error exists that allows cross-origin
    policy violations. (CVE-2014-0548)

  - A use-after-free error exists that allows arbitrary
    code execution. (CVE-2014-0553)

  - An unspecified error exists that allows an unspecified
    security bypass. (CVE-2014-0554)

  - Unspecified errors exist that allow memory leaks leading
    to easier defeat of memory address randomization.
    (CVE-2014-0557)

  - Heap-based buffer overflow errors exist that allow
    arbitrary code execution. (CVE-2014-0556, CVE-2014-0559)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-21.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 15.0.0.249 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player copyPixelsToByteArray Method Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
cutoff_version = '14.0.0.178';
fixed_version_for_report = '15.0.0.249';

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
