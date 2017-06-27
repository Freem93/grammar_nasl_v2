#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58208);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/29 14:07:11 $");

  script_cve_id("CVE-2012-0768", "CVE-2012-0769");
  script_bugtraq_id(52297, 52299);
  script_osvdb_id(79817, 79818);
  
  script_name(english:"Flash Player for Mac <= 10.3.183.15 / 11.1.102.62 Multiple Vulnerabilities (APSB12-05)");
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
the remote Mac OS X host is 10.x equal to or earlier than 10.3.183.15
or 11.x equal to or earlier than 11.1.102.62.  It is, therefore,
reportedly affected by several critical vulnerabilities :

  - A memory corruption vulnerability exists in Matrix3D 
    that could lead to code execution. (CVE-2012-0768)

  - Multiple integer errors exist that could lead to
    information disclosure. (CVE-2012-0769)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-05.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.183.16 / 11.1.102.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version    = "10.3.183.15";
tenx_fixed_version     = "10.3.183.16";
elevenx_cutoff_version = "11.1.102.62";
elevenx_fixed_version  = "11.1.102.63";
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
else exit(0, "The Flash Player for Mac "+version+" install is not affected.");
