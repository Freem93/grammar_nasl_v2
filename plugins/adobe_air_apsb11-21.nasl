#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55805);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

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
    49086
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
    74444
  );
  script_xref(name:"EDB-ID", value:"18437");
  script_xref(name:"EDB-ID", value:"18479");

  script_name(english:"Adobe AIR < 2.7.1 Multiple Vulnerabilities (APSB11-21)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR installed on the
remote Windows host is equal or prior to 2.7.1. It is, therefore,
affected by several critical vulnerabilities :

  - Multiple buffer overflow conditions exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2011-2130, CVE-2011-2134, CVE-2011-2137,
    CVE-2011-2414, CVE-2011-2415)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2011-2135, CVE-2011-2140, CVE-2011-2417,
    CVE-2011-2425)

  - Multiple integer overflow conditions exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2011-2136, CVE-2011-2138, CVE-2011-2416)

  - A same-origin bypass vulnerability exists that allows a
    remote attacker to obtain sensitive information.
    (CVE-2011-2139)");
  # http://www.abysssec.com/blog/2012/01/31/exploiting-cve-2011-2140-another-flash-player-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d1fce8");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 2.7.1 (2.7.1.19610) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

fix = '2.7.1.19610';
fix_ui = '2.7.1';

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Adobe AIR "+version_report+" is installed.");
