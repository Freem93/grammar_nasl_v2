#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71353);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2013-5331", "CVE-2013-5332");
  script_bugtraq_id(64199, 64201);
  script_osvdb_id(100774, 100775);

  script_name(english:"Flash Player for Mac <= 11.7.700.252 / 11.9.900.152 Multiple Vulnerabilities (APSB13-28)");
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
remote Mac OS X host is equal or prior to 11.7.700.252 / 11.8.x or
11.9.x equal or prior to 11.9.900.152.  It is, therefore, potentially
affected by the following vulnerabilities :

  - A type-confusion error exists that could allow
    arbitrary code execution. (CVE-2013-5331)

  - An input validation error exists that could allow
    denial of service attacks or possibly arbitrary code
    execution. (CVE-2013-5332)"
  );
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb13-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.257 / 11.9.900.170.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

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
eleven_sevenx_cutoff_version = "11.7.700.252";
eleven_sevenx_fixed_version = "11.7.700.257";

elevenx_cutoff_version = "11.9.900.152";
elevenx_fixed_version  = "11.9.900.170";

fixed_version_for_report = NULL;

if (version =~ "^([0-9]|10)\.|^11\.[0-6]")
  fixed_version_for_report = eleven_sevenx_fixed_version;

else if (
  version =~ "^11\.7\." &&
  ver_compare(ver:version, fix:eleven_sevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = eleven_sevenx_fixed_version;

else if (version =~ "^11\.8\.") fixed_version_for_report = elevenx_fixed_version;
else if (version =~ "^11\.9\." &&
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
