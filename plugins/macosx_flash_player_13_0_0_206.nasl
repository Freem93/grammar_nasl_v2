#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73741);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2014-0515");
  script_bugtraq_id(67092);
  script_osvdb_id(106347);

  script_name(english:"Flash Player for Mac <= 11.7.700.275 / 13.0.0.201 Pixel Bender Component Buffer Overflow (APSB14-13)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 11.7.700.275 / 11.8.x /
11.9.x / 12.x / 13.0.0.201. It is, therefore, potentially affected by
a buffer overflow vulnerability due to improper user input validation
in the Pixel Bender component. An attacker could cause a buffer
overflow with a specially crafted SWF file, resulting in arbitrary
code execution.");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-13.html");
  # https://www.securelist.com/en/blog/8212/New_Flash_Player_0_day_CVE_2014_0515_used_in_watering_hole_attacks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5043fc7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.279 / 13.0.0.206 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Shader Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

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
extended_cutoff_version = "11.7.700.275";
extended_fixed_version = "11.7.700.279";

standard_cutoff_version = "13.0.0.201";
standard_fixed_version  = "13.0.0.206";

fixed_version_for_report = NULL;

if (version =~ "^([0-9]|10)\.|^11\.[0-6]")
  fixed_version_for_report = extended_fixed_version;

else if (
  version =~ "^11\.7\." &&
  ver_compare(ver:version, fix:extended_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = extended_fixed_version;

else if (version =~ "^11\.[89]\." || version =~ "^12\.")
  fixed_version_for_report = standard_fixed_version;
else if (
  version =~ "^13\.0\.0\." &&
  ver_compare(ver:version, fix:standard_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = standard_fixed_version;

if (!isnull(fixed_version_for_report))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
