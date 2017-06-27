#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61487);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2012-2174");
  script_bugtraq_id(54070);
  script_osvdb_id(83063);

  script_name(english:"IBM Lotus Notes < 8.5.3 FP2 URL Handler Unspecified Remote Code Execution");
  script_summary(english:"Checks version of IBM Lotus Notes");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Lotus Notes prior to 8.5.3 Fix Pack
2 installed.  It is, therefore, reportedly affected by a remote code
execution vulnerability that an attacker can exploit by tricking a
victim into clicking a specially crafted 'notes://' URL.  

Note that this vulnerability can only be exploited when the software
is running in 'standard' mode."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-154/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/275");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21598348");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Notes 8.5.3 Fix Pack 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Lotus Notes Client URL Handler Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_notes_installed.nasl");
  script_require_keys("SMB/Lotus_Notes/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

fix = '8.5.32.12184';

if (
  version =~ "^8\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui + 
      '\n  Fixed version     : 8.5.3 FP2 (' + fix + ')' +
      '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
