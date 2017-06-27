#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93462);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2016-4271",
    "CVE-2016-4272",
    "CVE-2016-4274",
    "CVE-2016-4275",
    "CVE-2016-4276",
    "CVE-2016-4277",
    "CVE-2016-4278",
    "CVE-2016-4279",
    "CVE-2016-4280",
    "CVE-2016-4281",
    "CVE-2016-4282",
    "CVE-2016-4283",
    "CVE-2016-4284",
    "CVE-2016-4285",
    "CVE-2016-4287",
    "CVE-2016-6921",
    "CVE-2016-6922",
    "CVE-2016-6923",
    "CVE-2016-6924",
    "CVE-2016-6925",
    "CVE-2016-6926",
    "CVE-2016-6927",
    "CVE-2016-6929",
    "CVE-2016-6930",
    "CVE-2016-6931",
    "CVE-2016-6932"
  );
  script_osvdb_id(
    144112,
    144113,
    144114,
    144115,
    144116,
    144117,
    144118,
    144119,
    144120,
    144121,
    144122,
    144123,
    144124,
    144125,
    144126,
    144127,
    144128,
    144129,
    144130,
    144131,
    144132,
    144133,
    144134,
    144135,
    144136,
    144138
  );

  script_name(english:"Adobe Flash Player for Mac <= 22.0.0.211 Multiple Vulnerabilities (APSB16-29)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 22.0.0.211. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple security bypass vulnerabilities exist that
    allow an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2016-4271, CVE-2016-4277,
    CVE-2016-4278)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4272, CVE-2016-4279, CVE-2016-6921,
    CVE-2016-6923, CVE-2016-6925, CVE-2016-6926,
    CVE-2016-6927, CVE-2016-6929, CVE-2016-6930,
    CVE-2016-6931, CVE-2016-6932)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4274, CVE-2016-4275, CVE-2016-4276,
    CVE-2016-4280, CVE-2016-4281, CVE-2016-4282,
    CVE-2016-4283, CVE-2016-4284, CVE-2016-4285,
    CVE-2016-6922, CVE-2016-6924)

  - An integer overflow condition exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4287)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-29.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 23.0.0.162 or later.

Alternatively, Adobe has made version 18.0.0.375 available for those
installs that cannot be upgraded to the latest version");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"19.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "22.0.0.211";
  fix = "23.0.0.162";
}
else
{
  cutoff_version = "18.0.0.366";
  fix = "18.0.0.375";
}

# we're checking for versions less than or equal to the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
