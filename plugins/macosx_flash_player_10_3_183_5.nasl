#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55804);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2424",
    "CVE-2011-2425"
  );
  script_bugtraq_id(
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49186
  );
  script_osvdb_id(
    74432,
    74433,
    74434,
    74435,
    74436,
    74437,
    74438,
    74439,
    74440,
    74441,
    74442,
    74443,
    74444,
    75201
  );

  script_name(english:"Flash Player for Mac <= 10.3.181.36 Multiple Vulnerabilities (APSB11-21)");
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
the remote Mac OS X host is 10.3.181.36 or earlier.  As such, it is
reportedly affected by several critical vulnerabilities :

  - Multiple buffer overflow vulnerabilities could lead to
    code execution. (CVE-2011-2130, CVE-2011-2134, 
    CVE-2011-2137, CVE-2011-2414, CVE-2011-2415)

  - Multiple memory corruption vulnerabilities could lead to
    code execution. (CVE-2011-2135, CVE-2011-2140, 
    CVE-2011-2417, CVE-2011-2424, CVE-2011-2425)

  - Multiple integer overflow vulnerabilities could lead to
    code execution. (CVE-2011-2136, CVE-2011-2138, 
    CVE-2011-2416)

  - A cross-site information disclosure vulnerability 
    exists that could lead to code execution. 
    (CVE-2011-2139)

By tricking a user on the affected system into opening a specially
crafted document with Flash content, an attacker could leverage these
vulnerabilities to execute arbitrary code remotely on the system
subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Adobe Flash for Mac version 10.3.183.5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");

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

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = "10.3.181.36";
fixed_version = "10.3.183.5";

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
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
