#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64586);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2013-0637",
    "CVE-2013-0638",
    "CVE-2013-0639",
    "CVE-2013-0642",
    "CVE-2013-0644",
    "CVE-2013-0645",
    "CVE-2013-0647",
    "CVE-2013-0649",
    "CVE-2013-1365",
    "CVE-2013-1366",
    "CVE-2013-1367",
    "CVE-2013-1368",
    "CVE-2013-1369",
    "CVE-2013-1370",
    "CVE-2013-1372",
    "CVE-2013-1373",
    "CVE-2013-1374"
  );
  script_bugtraq_id(
    57912,
    57916,
    57917,
    57918,
    57919,
    57920,
    57921,
    57922,
    57923,
    57924,
    57925,
    57926,
    57927,
    57929,
    57930,
    57932,
    57933
  );
  script_osvdb_id(
    90095,
    90096,
    90097,
    90098,
    90099,
    90100,
    90101,
    90102,
    90103,
    90104,
    90105,
    90106,
    90107,
    90108,
    90109,
    90110,
    90111
  );

  script_name(english:"Flash Player for Mac <= 10.3.183.51 / 11.5.502.149 Multiple Vulnerabilities (APSB13-05)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X  host has a browser plugin that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Mac OS X host is 11.x equal or prior to 11.5.502.149, or 10.x
equal or prior to 10.3.183.51.  It is, therefore, potentially affected
by the following vulnerabilities :

  - Several unspecified issues exist that could lead to
    buffer overflows and arbitrary code execution.
    (CVE-2013-1372, CVE-2013-0645, CVE-2013-1373,
    CVE-2013-1369, CVE-2013-1370, CVE-2013-1366,
    CVE-2013-1365, CVE-2013-1368, CVE-2013-0642,
    CVE-2013-1367)

  - Several unspecified use-after-free vulnerabilities
    exist that could lead to remote code execution.
    (CVE-2013-0649, CVE-2013-1374, CVE-2013-0644)

  -  Two unspecified issues exists that could lead to
     memory corruption and arbitrary code execution.
     (CVE-2013-0638, CVE-2013-0647)

  - An unspecified information disclosure vulnerability exists.
    (CVE-2013-0637)

  - An unspecified integer overflow vulnerability exists.
    (CVE-2013-0639)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 10.3.183.61 / 11.6.602.167 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
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
tenx_cutoff_version = "10.3.183.51";
tenx_fixed_version = "10.3.183.61";
elevenx_cutoff_version = "11.5.502.149";
elevenx_fixed_version = "11.6.602.167";
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
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' +fixed_version_for_report + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
