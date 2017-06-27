#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73996);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2014-0510",
    "CVE-2014-0516",
    "CVE-2014-0517",
    "CVE-2014-0518",
    "CVE-2014-0519",
    "CVE-2014-0520"
  );
  script_bugtraq_id(66241, 67361, 67364, 67371, 67372, 67373);
  script_osvdb_id(104585, 106886, 106887, 106888, 106889, 106890);

  script_name(english:"Flash Player for Mac <= 13.0.0.206 Multiple Vulnerabilities (APSB14-14)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 13.0.0.206. It is,
therefore, potentially affected by the following vulnerabilities :

  - An unspecified use-after-free vulnerability exists that
    could allow for the execution of arbitrary code.
    (CVE-2014-0510)

  - An unspecified vulnerability exists that could be used
    to bypass the same origin policy. (CVE-2014-0516)

  - Multiple, unspecified security bypass vulnerabilities
    exist. (CVE-2014-0517, CVE-2014-0518, CVE-2014-0519,
    CVE-2014-0520)");
  script_set_attribute(attribute:"see_also", value:"http://www.pwn2own.com/2014/03/pwn2own-results-thursday-day-two/");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-14.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash Player version 13.0.0.214 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

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

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = "13.0.0.206";
fix = "13.0.0.214";

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
