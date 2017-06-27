#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66447);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2013-2728",
    "CVE-2013-3324",
    "CVE-2013-3325",
    "CVE-2013-3326",
    "CVE-2013-3327",
    "CVE-2013-3328",
    "CVE-2013-3329",
    "CVE-2013-3330",
    "CVE-2013-3331",
    "CVE-2013-3332",
    "CVE-2013-3333",
    "CVE-2013-3334",
    "CVE-2013-3335"
  );

  script_bugtraq_id(
    59889,
    59890,
    59891,
    59892,
    59893,
    59894,
    59895,
    59896,
    59897,
    59898,
    59899,
    59900,
    59901
  );
  script_osvdb_id(
    93322,
    93323,
    93324,
    93325,
    93326,
    93327,
    93328,
    93329,
    93330,
    93331,
    93332,
    93333,
    93334
  );

  script_name(english:"Flash Player for Mac <= 10.3.183.75 / 11.7.700.169 Multiple Vulnerabilities (APSB13-14)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Mac OS X host is 11.x equal or prior to 11.7.700.169, or 10.x
equal or prior to 10.3.183.75.  It is, therefore, potentially affected
by multiple memory corruption errors that could lead to code
execution.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 10.3.183.86 / 11.7.700.202 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
tenx_cutoff_version = "10.3.183.75";
tenx_fixed_version = "10.3.183.86";

elevenx_cutoff_version = "11.7.700.169";
elevenx_fixed_version  = "11.7.700.202";
fixed_version_for_report = NULL;

if (ver_compare(ver:version, fix:tenx_cutoff_version, strict:FALSE) <= 0) 
  fixed_version_for_report = tenx_fixed_version;

if (
  version =~ "^11\." &&
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
