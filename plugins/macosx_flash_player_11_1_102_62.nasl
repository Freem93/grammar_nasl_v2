#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58002);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2012-0752",
    "CVE-2012-0753",
    "CVE-2012-0754",
    "CVE-2012-0755",
    "CVE-2012-0756",
    "CVE-2012-0767"
  );
  script_bugtraq_id(
    52032,
    52033,
    52034,
    52035,
    52036,
    52040
  );
  script_osvdb_id(
    79296,
    79297,
    79298,
    79299,
    79300,
    79301,
    79302
  );
  script_xref(name:"ZDI", value:"ZDI-12-080");
  
  script_name(english:"Flash Player for Mac <= 10.3.183.14 / 11.1.102.62 Multiple Vulnerabilities (APSB12-03)");
  script_summary(english:"Checks version of Flash Player from Info.plist");

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
the remote Mac OS X host is 10.x equal to or earlier than 10.3.183.14
or 11.x equal to or earlier than 11.1.102.62.  It is, therefore,
reportedly affected by several critical vulnerabilities :

  - An unspecified memory corruption issue exists that could
    lead to code execution. (CVE-2012-0754)

  - An unspecified type confusion memory corruption 
    vulnerability exists that could lead to code execution.
    (CVE-2012-0752)

  - An MP4 parsing memory corruption issue exists that
    could lead to code execution. (CVE-2012-0753)

  - Multiple unspecified security bypass vulnerabilities
    exist that could lead to code execution. (CVE-2012-0755,
    CVE-2012-0756)

  - A universal cross-site scripting issue exists that could
    be used to take actions on a user's behalf on any
    website or webmail provider. (CVE-2012-0767)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-080/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/67");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-03.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.183.15 / 11.1.102.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 \'cprt\' Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");

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


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version    = "10.3.183.14";
tenx_fixed_version     = "10.3.183.15";
elevenx_cutoff_version = "11.1.102.55";
elevenx_fixed_version  = "11.1.102.62";
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
