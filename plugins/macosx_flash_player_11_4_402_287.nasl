#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62482);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2012-5248",
    "CVE-2012-5249",
    "CVE-2012-5250",
    "CVE-2012-5251",
    "CVE-2012-5252",
    "CVE-2012-5253",
    "CVE-2012-5254",
    "CVE-2012-5255",
    "CVE-2012-5256",
    "CVE-2012-5257",
    "CVE-2012-5258",
    "CVE-2012-5259",
    "CVE-2012-5260",
    "CVE-2012-5261",
    "CVE-2012-5262",
    "CVE-2012-5263",
    "CVE-2012-5264",
    "CVE-2012-5265",
    "CVE-2012-5266",
    "CVE-2012-5267",
    "CVE-2012-5268",
    "CVE-2012-5269",
    "CVE-2012-5270",
    "CVE-2012-5271",
    "CVE-2012-5272",
    "CVE-2012-5285",
    "CVE-2012-5286",
    "CVE-2012-5287",
    "CVE-2012-5673"
  );
  script_bugtraq_id(
    56198,
    56200,
    56201,
    56202,
    56203,
    56204,
    56205,
    56206,
    56207,
    56208,
    56209,
    56210,
    56211,
    56212,
    56213,
    56214,
    56215,
    56216,
    56217,
    56218,
    56219,
    56220,
    56221,
    56222,
    56224,
    56374,
    56375,
    56376,
    56377
  );
  script_osvdb_id(
    86025,
    86026,
    86027,
    86028,
    86029,
    86030,
    86031,
    86032,
    86033,
    86034,
    86035,
    86036,
    86037,
    86038,
    86039,
    86040,
    86041,
    86042,
    86043,
    86044,
    86045,
    86046,
    86047,
    86048,
    86049,
    86874,
    86875,
    86876,
    86877
  );

  script_name(english:"Flash Player for Mac <= 10.3.183.23 / 11.4.402.265 Multiple Vulnerabilities (APSB12-22)");
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
remote Mac OS X host is 11.x equal to or earlier than 11.4.402.264, or
10.x equal to or earlier than 10.3.183.23.  It is, therefore,
potentially affected by multiple vulnerabilities :

  - Several unspecified issues exist that can lead to buffer
    overflows and arbitrary code execution. (CVE-2012-5248,
    CVE-2012-5249, CVE-2012-5250, CVE-2012-5251,
    CVE-2012-5253, CVE-2012-5254, CVE-2012-5255,
    CVE-2012-5257, CVE-2012-5259, CVE-2012-5260,
    CVE-2012-5262, CVE-2012-5264, CVE-2012-5265,
    CVE-2012-5266, CVE-2012-5285, CVE-2012-5286,
    CVE-2012-5287)

  - Several unspecified issues exist that can lead to memory
    corruption and arbitrary code execution. (CVE-2012-5252,
    CVE-2012-5256, CVE-2012-5258, CVE-2012-5261,
    CVE-2012-5263, CVE-2012-5267, CVE-2012-5268,
    CVE-2012-5269, CVE-2012-5270, CVE-2012-5271,
    CVE-2012-5272)

  - An unspecified issue exists having unspecified impact.
    (CVE-2012-5673)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-22.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.29, 11.4.402.287 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version = "10.3.183.23";
tenx_fixed_version = "10.3.183.29";
elevenx_cutoff_version = "11.4.402.265";
elevenx_fixed_version = "11.4.402.287";
fixed_version_for_report = NULL;

# 10x
if (ver_compare(ver:version, fix:tenx_cutoff_version, strict:FALSE) <= 0)
  fixed_version_for_report = tenx_fixed_version;

# 11x
if (
  version =~ "^11\." &&
  ver_compare(ver:version, fix:elevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = elevenx_fixed_version;

if (!isnull(fixed_version_for_report))
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Flash Player for Mac", version);
