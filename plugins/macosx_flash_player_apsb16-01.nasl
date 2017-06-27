#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87659);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:42:41 $");

  script_cve_id(
    "CVE-2015-8459",
    "CVE-2015-8460",
    "CVE-2015-8634",
    "CVE-2015-8635",
    "CVE-2015-8636",
    "CVE-2015-8638",
    "CVE-2015-8639",
    "CVE-2015-8640",
    "CVE-2015-8641",
    "CVE-2015-8642",
    "CVE-2015-8643",
    "CVE-2015-8644",
    "CVE-2015-8645",
    "CVE-2015-8646",
    "CVE-2015-8647",
    "CVE-2015-8648",
    "CVE-2015-8649",
    "CVE-2015-8650",
    "CVE-2015-8651"
  );
  script_osvdb_id(
    132309,
    132310,
    132311,
    132312,
    132313,
    132314,
    132315,
    132316,
    132317,
    132318,
    132319,
    132320,
    132321,
    132322,
    132323,
    132324,
    132325,
    132326,
    132327
  );

  script_name(english:"Adobe Flash Player for Mac <= 20.0.0.235 Multiple Vulnerabilities (APSB16-01)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 20.0.0.235. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that a remote attacker can
    exploit to execute arbitrary code. (CVE-2015-8644)

  - An integer overflow condition exists that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8651)

  - Multiple use-after-free errors exist that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8634, CVE-2015-8635, CVE-2015-8638,
    CVE-2015-8639, CVE-2015-8640, CVE-2015-8641,
    CVE-2015-8642, CVE-2015-8643, CVE-2015-8646,
    CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
    CVE-2015-8650)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2015-8459, CVE-2015-8460, CVE-2015-8636,
    CVE-2015-8645)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 20.0.0.267 or later.

Alternatively, Adobe has made version 18.0.0.324 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");

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

if (version =~ "^(19|20)\.")
{
  cutoff_version = "20.0.0.235";
  fix = "20.0.0.267";
}
else
{
  cutoff_version = "18.0.0.268";
  fix = "18.0.0.324";
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
