#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73435);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id(
    "CVE-2014-0506",
    "CVE-2014-0507",
    "CVE-2014-0508",
    "CVE-2014-0509"
  );
  script_bugtraq_id(66208, 66699, 66701, 66703);
  script_osvdb_id(104598, 105535, 105536, 105537);

  script_name(english:"Flash Player for Mac <= 11.7.700.272 / 12.0.0.77 Multiple Vulnerabilities (APSB14-09) (Mac OS X)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 11.7.700.272 / 11.8.x /
11.9.x / 12.0.0.77. It is, therefore, potentially affected by multiple
vulnerabilities :

  - A use-after-free error exists that could lead to
    arbitrary code execution. (CVE-2014-0506)

  - A buffer overflow error exists that could lead to
    arbitrary code execution. (CVE-2014-0507)

  - An unspecified error exists that could allow a security
    bypass leading to information disclosure.
    (CVE-2014-0508)

  - An unspecified error exists that could allow cross-
    site scripting attacks. (CVE-2014-0509)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.275 / 13.0.0.182 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
extended_cutoff_version = "11.7.700.272";
extended_fixed_version = "11.7.700.275";

standard_cutoff_version = "12.0.0.77";
standard_fixed_version  = "13.0.0.182";

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
  # XSS
  set_kb_item(name:'www/0/XSS', value: TRUE);

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
