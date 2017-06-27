#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96389);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id(
    "CVE-2017-2925",
    "CVE-2017-2926",
    "CVE-2017-2927",
    "CVE-2017-2928",
    "CVE-2017-2930",
    "CVE-2017-2931",
    "CVE-2017-2932",
    "CVE-2017-2933",
    "CVE-2017-2934",
    "CVE-2017-2935",
    "CVE-2017-2936",
    "CVE-2017-2937",
    "CVE-2017-2938"
  );
  script_bugtraq_id(
    95341,
    95342,
    95347,
    95350
  );
  script_osvdb_id(
    149841,
    149842,
    149843,
    149844,
    149845,
    149846,
    149847,
    149848,
    149849,
    149850,
    149851,
    149852,
    149853
  );

  script_name(english:"Adobe Flash Player for Mac <= 24.0.0.186 Multiple Vulnerabilities (APSB17-02)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host has a browser plugin installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac
OS X host is equal or prior to version 24.0.0.186. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-2925, CVE-2017-2926, CVE-2017-2928,
    CVE-2017-2930, CVE-2017-2931)

  - Multiple heap buffer overflow conditions exist that
    allow an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-2927, CVE-2017-2933,
    CVE-2017-2934, CVE-2017-2935)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-2932, CVE-2017-2936, CVE-2017-2937)

  - A security bypass vulnerability exists that allows an
    unauthenticated, remote attacker to disclose sensitive
    information. (CVE-2017-2938)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-02.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 24.0.0.194 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

cutoff_version = "24.0.0.186";
fix = "24.0.0.194";
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
