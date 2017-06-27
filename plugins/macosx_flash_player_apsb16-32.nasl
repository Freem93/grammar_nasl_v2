#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93961);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2016-4273",
    "CVE-2016-4286",
    "CVE-2016-6981",
    "CVE-2016-6982",
    "CVE-2016-6983",
    "CVE-2016-6984",
    "CVE-2016-6985",
    "CVE-2016-6986",
    "CVE-2016-6987",
    "CVE-2016-6989",
    "CVE-2016-6990",
    "CVE-2016-6992"
  );
  script_bugtraq_id(
    93488,
    93490,
    93492,
    93497
  );
  script_osvdb_id(
    145407,
    145408,
    145409,
    145410,
    145411,
    145412,
    145413,
    145414,
    145415,
    145416,
    145417,
    145418
  );

  script_name(english:"Adobe Flash Player for Mac <= 23.0.0.162 Multiple Vulnerabilities (APSB16-32)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 23.0.0.162. It is, therefore,
affected by multiple vulnerabilities :

  - A type confusion error exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-6992)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-6981, CVE-2016-6987)

  - An unspecified security bypass vulnerability exists that
    allows an unauthenticated, remote attacker to bypass
    security restrictions. (CVE-2016-4286)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4273, CVE-2016-6982, CVE-2016-6983,
    CVE-2016-6984, CVE-2016-6985, CVE-2016-6986,
    CVE-2016-6989, CVE-2016-6990)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-32.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 23.0.0.185 or later.

Alternatively, Adobe has made version 18.0.0.382 available for those installs
that cannot be upgraded to the latest version");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");

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
  cutoff_version = "23.0.0.162";
  fix = "23.0.0.185";
}
else
{
  cutoff_version = "18.0.0.375";
  fix = "18.0.0.382";
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
