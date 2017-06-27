#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86854);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

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

  script_name(english:"Adobe Flash Player for Mac <= 19.0.0.226 Multiple Vulnerabilities (APSB15-28)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 19.0.0.226. It is, therefore,
affected by multiple vulnerabilities :

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
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.245 or later.

Alternatively, Adobe has made version 18.0.0.261 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (version =~ "^19\.")
{
  cutoff_version = "19.0.0.226";
  fix = "19.0.0.245";
}
else
{
  cutoff_version = "18.0.0.255";
  fix = "18.0.0.261";
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
