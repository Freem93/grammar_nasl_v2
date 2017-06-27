#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71953);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/02/17 03:02:06 $");

  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_bugtraq_id(64807, 64810);
  script_osvdb_id(101982, 101983);

  script_name(english:"Flash Player for Mac <= 11.7.700.257 / 11.9.900.170 Multiple Vulnerabilities (APSB14-02)");
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
remote Mac OS X host is equal or prior to 11.7.700.257 / 11.8.x or
11.9.x equal or prior to 11.9.900.170.  It is, therefore, potentially
affected by the following vulnerabilities :

  - An unspecified vulnerability exists that can be used to
    bypass Flash Player security protections.
    (CVE-2014-0491)

  - An unspecified vulnerability exists that can be used to
    bypass memory address layout randomization.
    (CVE-2014-0492)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-014/");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.260 / 12.0.0.38 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
eleven_sevenx_cutoff_version = "11.7.700.257";
eleven_sevenx_fixed_version = "11.7.700.260";

elevenx_cutoff_version = "11.9.900.170";
elevenx_fixed_version  = "12.0.0.38";

fixed_version_for_report = NULL;

if (version =~ "^([0-9]|10)\.|^11\.[0-6]")
  fixed_version_for_report = eleven_sevenx_fixed_version;

else if (
  version =~ "^11\.7\." &&
  ver_compare(ver:version, fix:eleven_sevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = eleven_sevenx_fixed_version;

else if (version =~ "^11\.8\.") fixed_version_for_report = elevenx_fixed_version;
else if (
  version =~ "^11\.9\." &&
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
