#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72607);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2014-0498", "CVE-2014-0499", "CVE-2014-0502");
  script_bugtraq_id(65702, 65703, 65704);
  script_osvdb_id(103518, 103519, 103520);

  script_name(english:"Flash Player for Mac <= 11.7.700.261 / 12.0.0.44 Multiple Vulnerabilities (APSB14-07) (Mac OS X)");
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
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 11.7.700.261 / 11.8.x /
11.9.x / 12.0.0.44.  It is, therefore, potentially affected by
multiple vulnerabilities :

  - A stack overflow vulnerability exists that could result
    in arbitrary code execution. (CVE-2014-0498)

  - A memory leak vulnerability exists that could be used
    to aid in buffer overflow attacks by bypassing address
    space layout randomization (ASLR). (CVE-2014-0499)

  - A double free vulnerability exists that could result in
    arbitrary code execution. (CVE-2014-0502)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-040/");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.269 / 12.0.0.70 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");

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
extended_cutoff_version = "11.7.700.261";
extended_fixed_version = "11.7.700.269";

standard_cutoff_version = "12.0.0.44";
standard_fixed_version  = "12.0.0.70";

fixed_version_for_report = NULL;

if (version =~ "^([0-9]|10)\.|^11\.[0-6]")
  fixed_version_for_report = extended_fixed_version;

else if (
  version =~ "^11\.7\." &&
  ver_compare(ver:version, fix:extended_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = extended_fixed_version;

else if (version =~ "^11\.[89]\.") fixed_version_for_report = standard_fixed_version;
else if (
  version =~ "^12\.0\.0\." &&
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
