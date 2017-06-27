#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79143);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2014-0573",
    "CVE-2014-0574",
    "CVE-2014-0576",
    "CVE-2014-0577",
    "CVE-2014-0581",
    "CVE-2014-0582",
    "CVE-2014-0583",
    "CVE-2014-0584",
    "CVE-2014-0585",
    "CVE-2014-0586",
    "CVE-2014-0588",
    "CVE-2014-0589",
    "CVE-2014-0590",
    "CVE-2014-8437",
    "CVE-2014-8438",
    "CVE-2014-8440",
    "CVE-2014-8441",
    "CVE-2014-8442"
  );
  script_bugtraq_id(
    71033,
    71035,
    71036,
    71037,
    71038,
    71039,
    71040,
    71041,
    71042,
    71043,
    71044,
    71045,
    71046,
    71047,
    71048,
    71049,
    71050,
    71051
  );
  script_osvdb_id(
    114487,
    114488,
    114489,
    114490,
    114491,
    114492,
    114493,
    114494,
    114495,
    114496,
    114497,
    114498,
    114499,
    114500,
    114501,
    114502,
    114503,
    114504
  );

  script_name(english:"Flash Player For Mac <= 15.0.0.189 Multiple Vulnerabilities (APSB14-24)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe Flash Player
installed on the remote Mac OS X host is equal or prior to 15.0.0.189.
It is, therefore, affected by the following vulnerabilities :

  - Multiple memory corruption vulnerabilities allow an
    attacker to execute arbitrary code. (CVE-2014-0576,
    CVE-2014-0581, CVE-2014-8440, CVE-2014-8441)

  - Multiple use-after-free vulnerabilities could result in
    arbitrary code execution. (CVE-2014-0573, CVE-2014-0588,
    CVE-2014-8438, CVE-2014-0574)

  - Multiple type confusion vulnerabilities could result in
    arbitrary code execution. (CVE-2014-0577, CVE-2014-0584,
    CVE-2014-0585, CVE-2014-0586, CVE-2014-0590)

  - Multiple heap-based buffer overflow vulnerabilities can
    be exploited to execute arbitrary code or elevate
    privileges. (CVE-2014-0583, CVE-2014-0582,
    CVE-2014-0589)

  - A permission issue that allows a remote attacker to gain
    elevated privileges. (CVE-2014-8442)

  - An information disclosure vulnerability can be exploited
    to disclose secret session tokens. (CVE-2014-8437)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-24.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 15.0.0.223 or later.

Alternatively, Adobe has made version 13.0.0.252 available for those
installations that cannot be upgraded to 15.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player UncompressViaZlibVariant Uninitialized Memory');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"14.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "15.0.0.189";
  fix = "15.0.0.223";
}
else
{
  cutoff_version = "13.0.0.250";
  fix = "13.0.0.252";
}

# nb: we're checking for versions less than *or equal to* the cutoff!
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
