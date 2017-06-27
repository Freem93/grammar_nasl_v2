#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53915);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/18 14:06:55 $");

  script_cve_id(
    "CVE-2011-0579",
    "CVE-2011-0618",
    "CVE-2011-0619",
    "CVE-2011-0620",
    "CVE-2011-0621",
    "CVE-2011-0622",
    "CVE-2011-0623",
    "CVE-2011-0624",
    "CVE-2011-0625",
    "CVE-2011-0626",
    "CVE-2011-0627"
  );
  script_bugtraq_id(
    47806, 
    47807, 
    47808, 
    47809,
    47810,
    47811,
    47812,
    47813,
    47814,
    47815,
    47847
  );
  script_osvdb_id(
    72331,
    72332,
    72333,
    72334,
    72335,
    72336,
    72337,
    72341,
    72342,
    72343,
    72344
  );

  script_name(english:"Flash Player for Mac < 10.3.181.14 Remote Code Execution (APSB11-12)");
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
the remote Mac OS X host is earlier than 10.3.181.14.  Such versions
are reportedly affected by the following vulnerabilities :

  - An unspecified information disclosure vulnerability
    exists. (CVE-2011-0579)

  - An unspecified integer overflow vulnerability exists.
    (CVE-2011-0618)

  - Unspecified memory corruption vulnerabilities exist.
    (CVE-2011-0619, CVE-2011-0620, CVE-2011-0621, 
    CVE-2011-0622, CVE-2011-0627)

  - Unspecified boundary-checking errors exist.
    (CVE-2011-0623, CVE-2011-0624, CVE-2011-0625,
    CVE-2011-0626)" );
 
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Adobe Flash for Mac version 10.3.181.14 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
fixed_version = "10.3.181.14";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "Flash Player for Mac "+version+" is installed and thus not affected.");
