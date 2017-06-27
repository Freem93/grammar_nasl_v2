#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49260);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2010-1818", "CVE-2010-1819");
  script_bugtraq_id(42774, 42841);
  script_osvdb_id(67591, 67705);

  script_name(english:"QuickTime < 7.6.8 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that is affected by
two vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of QuickTime installed on the remote Windows host is
older than 7.6.8.  Such versions are reportedly affected by two 
vulnerabilities :

  - An input validation issue in the QTPlugin.ocx ActiveX 
    control could allow an attacker to force the application 
    to jump to a location in memory controlled by the
    attacker through the optional '_Marshaled_pUnk' 
    parameter and in turn to execute remote code under the 
    context of the user running the web browser. 
    (CVE-2010-1818)

  - QuickTime Picture Viewer uses a fixed path to look for 
    specific files or libraries, such as 'cfnetwork.dll' 
    and 'corefoundation.dll', and this path includes 
    directories that may not be trusted or under user 
    control. If an attacker places a maliciously crafted 
    DLL in the same directory as an image file, opening 
    the image file with QuickTime Picture Viewer will cause
    the malicious DLL to be loaded. (CVE-2010-1819)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://zerodayinitiative.com/advisories/ZDI-10-168/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2010/Aug/372"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?056a1d24"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4339"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Sep/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to QuickTime 7.6.8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.6.7 _Marshaled_pUnk Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "SMB/QuickTime/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item(kb_base+"Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "7.68.75.0";
fixed_version_ui = "7.6.8 (1675)";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base+"Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since QuickTime "+version_report+" is installed.");
