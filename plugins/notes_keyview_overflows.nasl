#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27534);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2007-4222", "CVE-2007-5909", "CVE-2007-5910");
  script_bugtraq_id(26175, 26200);
  script_osvdb_id(
    40783,
    40786,
    40787,
    40788,
    40789,
    40790,
    40791,
    40792,
    40949
  );

  script_name(english:"Lotus Notes Client < 7.0.3 / 8.0.1 Multiple Overflows");
  script_summary(english:"Checks version of Lotus Notes"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by several
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote Windows host is
reportedly affected by several buffer overflows in its file attachment
viewer when handling attachments of various types.  By sending a
specially crafted attachment to users of the affected application and
getting them to double-click and view the attachment, an attacker may
be able to execute arbitrary code subject to the privileges under
which the affected application runs. 

It is also affected by another buffer overflow vulnerability in the
TagAttributeListCopy function in ''nnotes.dll'' that could be
triggered when a specially crafted message is replied to, forwarded,
or copied to the clipboard by a user of the application.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482664/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21271111");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21272836");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c52c5e1e");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482738");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21272930");
  script_set_attribute(attribute:"solution", value: "Upgrade to Lotus Notes version 7.0.3 / 8.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "lotus_notes_installed.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password","SMB/Lotus_Notes/Installed");
  script_require_ports("Services/notes", 139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";
version = get_kb_item_or_exit(kb_base + 'Version');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');
path = get_kb_item_or_exit(kb_base + 'Path');

ver = split(version, sep:'.', keep:FALSE);

# If it's an affected version...
#
# nb: ver[2] is multiplied by 10.
if (
  (int(ver[0]) == 6 && int(ver[1]) == 5) ||
  (int(ver[0]) == 7 && int(ver[1]) == 0 && int(ver[2]) < 30) ||
  (int(ver[0]) == 8 && int(ver[1]) == 0 && int(ver[2]) < 10)
) 
{
  if (report_verbosity > 0)
  {
    if (ver[0] == 6 || ver[0] == 7) fix = "7.0.3";
    else fix = "8.0.1";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0); 
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
