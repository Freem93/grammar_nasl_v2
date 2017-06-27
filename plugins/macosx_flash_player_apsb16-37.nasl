#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94629);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 15:55:07 $");

  script_cve_id(
    "CVE-2016-7857",
    "CVE-2016-7858",
    "CVE-2016-7859",
    "CVE-2016-7860",
    "CVE-2016-7861",
    "CVE-2016-7862",
    "CVE-2016-7863",
    "CVE-2016-7864",
    "CVE-2016-7865"
  );
  script_bugtraq_id(94151, 94153);
  script_osvdb_id(
    146854,
    146855,
    146856,
    146857,
    146858,
    146859,
    146860,
    146861,
    146862
  );

  script_name(english:"Adobe Flash Player for Mac <= 23.0.0.205 Multiple Vulnerabilities (APSB16-37)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host has a browser plugin installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac
OS X host is equal or prior to version 23.0.0.205. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code by convincing a user to visit a website containing
    specially crafted Flash content. (CVE-2016-7857,
    CVE-2016-7858, CVE-2016-7859, CVE-2016-7862,
    CVE-2016-7863, CVE-2016-7864)

  - Multiple type confusion errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code by convincing a user to visit a website containing
    specially crafted Flash content. (CVE-2016-7860,
    CVE-2016-7861, CVE-2016-7865)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-37.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 23.0.0.207 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

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

cutoff_version = "23.0.0.205";
fix = "23.0.0.207";
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
