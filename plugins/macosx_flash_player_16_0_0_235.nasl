#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79837);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2014-0580",
    "CVE-2014-0587",
    "CVE-2014-8443",
    "CVE-2014-9162",
    "CVE-2014-9163",
    "CVE-2014-9164"
  );
  script_bugtraq_id(
    71581,
    71582,
    71583,
    71584,
    71585,
    71586
  );
  script_osvdb_id(
    115557,
    115558,
    115559,
    115560,
    115561,
    115564
  );

  script_name(english:"Flash Player For Mac <= 15.0.0.239 Multiple Vulnerabilities (APSB14-27)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe Flash Player
installed on the remote Mac OS X host is equal or prior to 15.0.0.239.
It is, therefore, affected by the following vulnerabilities :

  - A security bypass vulnerability that allows an attacker
    to bypass the same-origin policy. (CVE-2014-0580)

  - Multiple memory corruption vulnerabilities that allow an
    attacker to execute arbitrary code. (CVE-2014-0587,
    CVE-2014-9164)

  - A use-after-free vulnerability that can result in
    arbitrary code execution. (CVE-2014-8443)

  - An unspecified information disclosure vulnerability.
    (CVE-2014-9162)

  - A stack-based buffer overflow vulnerability that can be
    exploited to execute arbitrary code or elevate
    privileges. (CVE-2014-9163)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-27.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 16.0.0.235 or later.

Alternatively, Adobe has made version 13.0.0.259 available for those
installations that cannot be upgraded to 16.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

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
  cutoff_version = "15.0.0.239";
  fix = "16.0.0.235";
}
else
{
  cutoff_version = "13.0.0.258";
  fix = "13.0.0.259";
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
