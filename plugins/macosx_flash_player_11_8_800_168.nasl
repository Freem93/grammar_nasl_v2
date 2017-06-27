#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69868);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/17 03:37:30 $");

  script_cve_id(
    "CVE-2013-3361",
    "CVE-2013-3362",
    "CVE-2013-3363",
    "CVE-2013-5324"
  );
  script_bugtraq_id(62290, 62294, 62295, 62296);
  script_osvdb_id(97050, 97051, 97052, 97053);

  script_name(english:"Flash Player for Mac <= 11.7.700.232 / 11.8.800.94 Memory Corruptions (APSB13-21)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Mac OS X host is equal or prior to 10.3.183.90 / 11.x equal or
prior to 11.7.700.232 / 11.8.x equal or prior to 11.8.800.94.  It is,
therefore, potentially affected by multiple memory corruption
vulnerabilities that could lead to code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-21.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 11.7.700.242 / 11.8.800.168 or
later, or Google Chrome Flash 11.8.800.170 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
tenx_cutoff_version = "10.3.183.90";
tenx_fixed_version = "11.7.700.242";

elevenx_sevenx_cutoff_version = "11.7.700.232";
elevenx_sevenx_fixed_version = "11.7.700.242";

elevenx_cutoff_version = "11.8.800.94";
elevenx_fixed_version  = "11.8.800.168";

fixed_version_for_report = NULL;

if (
  version =~ "^([0-9]|10)\." &&
  ver_compare(ver:version, fix:tenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = tenx_fixed_version;

if (
  version =~ "^11\.[0-7]\." &&
  ver_compare(ver:version, fix:elevenx_sevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = elevenx_sevenx_fixed_version;

if (
  version =~ "^11\.8\." &&
  ver_compare(ver:version, fix:elevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = elevenx_fixed_version;

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
