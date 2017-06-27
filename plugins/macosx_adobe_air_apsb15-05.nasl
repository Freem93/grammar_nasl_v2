#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84159);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2015-0332",
    "CVE-2015-0333",
    "CVE-2015-0334",
    "CVE-2015-0335",
    "CVE-2015-0336",
    "CVE-2015-0337",
    "CVE-2015-0338",
    "CVE-2015-0339",
    "CVE-2015-0340",
    "CVE-2015-0341",
    "CVE-2015-0342"
  );
  script_bugtraq_id(
    73080,
    73081,
    73082,
    73083,
    73084,
    73085,
    73086,
    73087,
    73088,
    73089,
    73091
  );
  script_osvdb_id(
    119386,
    119479,
    119480,
    119481,
    119482,
    119483,
    119484,
    119485,
    119486,
    119487,
    119488
  );

  script_name(english:"Adobe AIR for Mac <= 17.0.0.124 Multiple Vulnerabilities (APSB15-05)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a version of Adobe AIR installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Mac OS X host is equal or prior to 17.0.0.124. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. An attacker can
    exploit these flaws to execute arbitrary code.
    (CVE-2015-0332, CVE-2015-0333, CVE-2015-0335,
    CVE-2015-0339)

  - Multiple type confusions flaws exist that allow an
    attacker to execute arbitrary code. (CVE-2015-0334,
    CVE-2015-0336)

  - A unspecified flaw exists that allows an attacker to
    bypass cross-domain policy. (CVE-2015-0337)

  - An integer overflow condition exists due improper
    validation of user-supplied input. An attacker can
    exploit to execute arbitrary code. (CVE-2015-0338)

  - A unspecified flaw exists that allows an attacker to
    bypass restrictions and upload arbitrary files.
    (CVE-2015-0340)

  - Multiple use-after-free errors exist that allow an
    attacker to deference already freed memory and execute
    arbitrary code. (CVE-2015-0341, CVE-2015-0342)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-05.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 17.0.0.144 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player NetConnection Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

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
cutoff_version = '17.0.0.124';
fixed_version_for_report = '17.0.0.144';

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
