#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81820);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

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
  script_xref(name:"EDB-ID", value:"36962");

  script_name(english:"Flash Player For Mac <= 16.0.0.305 Multiple Vulnerabilities (APSB15-05)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Adobe Flash Player installed on the
remote Mac OS X host is equal or prior to version 16.0.0.305. It is,
therefore, affected by the following vulnerabilities :

  - Multiple memory corruption issues exist due to not
    properly validating user input, which an attacker can
    exploit to execute arbitrary code. (CVE-2015-0332,
    CVE-2015-0333, CVE-2015-0335, CVE-2015-0339)

  - Multiple type confusions flaws exist, which an attacker
    can exploit to execute arbitrary code. (CVE-2015-0334,
    CVE-2015-0336)

  - An unspecified flaw exists that allows an attacker to
    bypass cross-domain policy. (CVE-2015-0337)

  - An integer overflow condition exists due to not properly
    validating user input, which an attacker can exploit to
    execute arbitrary code. (CVE-2015-0338)

  - An unspecified flaw exists that allows an attacker to
    bypass restrictions and upload arbitrary files.
    (CVE-2015-0340)

  - Multiple use-after-free errors exist that can allow an
    attacker to deference already freed memory and execute
    arbitrary code. (CVE-2015-0341, CVE-2015-0342)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-05.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 17.0.0.134 or later.

Alternatively, Adobe has made version 13.0.0.277 available for those
installations that cannot be upgraded to 17.x.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

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

if (ver_compare(ver:version, fix:"14.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "16.0.0.305";
  fix = "17.0.0.134";
}
else
{
  cutoff_version = "13.0.0.269";
  fix = "13.0.0.277";
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
