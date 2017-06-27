#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53474);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2011-0611");
  script_bugtraq_id(47314);
  script_osvdb_id(71686);
  script_xref(name:"CERT", value:"230057");
  script_xref(name:"Secunia", value:"44119");

  script_name(english:"Adobe AIR < 2.6.0.19140 ActionScript Predefined Class Prototype Addition Remote Code Execution (APSB11-07)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a version of Adobe AIR that allows
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe AIR earlier than
2.6.0.19140.  Such versions are reportedly affected by a memory
corruption vulnerability. 

By tricking a user on the affected system into opening a specially
crafted document with Flash content, such as a SWF file embedded in a
Microsoft Word document, an attacker can potentially leverage this
issue to execute arbitrary code remotely on the system subject to the
user's privileges. 

Note that there are reports that this issue is being exploited in the
wild as of April 2011.");
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?9ee82b34");
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb11-07.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Adobe AIR 2.6.0.19140 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value: "2011/04/11");
  script_set_attribute(attribute:"patch_publication_date", value: "2011/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");
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

fix = '2.6.0.19140';
fix_ui = '2.6';

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
