#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97728);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id(
    "CVE-2017-2997",
    "CVE-2017-2998",
    "CVE-2017-2999",
    "CVE-2017-3000",
    "CVE-2017-3001",
    "CVE-2017-3002",
    "CVE-2017-3003"
  );
  script_bugtraq_id(
    96860,
    96861,
    96862,
    96866
  );
  script_osvdb_id(
    153612,
    153613,
    153614,
    153618,
    153619,
    153620,
    153621
  );

  script_name(english:"Adobe Flash Player for Mac <= 24.0.0.221 Multiple Vulnerabilities (APSB17-07)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host has a browser plugin installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote macOS or Mac
OS X host is equal or prior to version 24.0.0.221. It is, therefore,
affected by multiple vulnerabilities :

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2017-2997)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2017-2998,
    CVE-2017-2999)

  - An unspecified flaw exists in the random number
    generator used for constant binding that allows an
    attacker to disclose sensitive information.
    (CVE-2017-3000)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2017-3001,
    CVE-2017-3002, CVE-2017-3003)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-07.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 25.0.0.127 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

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

cutoff_version = "24.0.0.221";
fix = "25.0.0.127";
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
