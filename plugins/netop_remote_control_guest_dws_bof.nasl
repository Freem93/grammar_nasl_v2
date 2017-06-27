#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58769);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:42 $");

  script_bugtraq_id(47631);
  script_osvdb_id(72291);
  script_xref(name:"EDB-ID", value:"17223");
  script_xref(name:"EDB-ID", value:"18697");

  script_name(english:"Netop Remote Control dws File Handling Overflow");
  script_summary(english:"Checks version of Netop Remote Control Guest install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"There is an application installed on the remote host that is affected
by a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Netop Remote Control Guest is installed on the remote Windows host
and is less than version 10.0 build 2011087.  As such, it reportedly
has a flaw in handling '.dws' script files that can be utilized to
trigger a buffer overflow. 

By tricking the user into opening a specially crafted '.dws' file, a
remote attacker may be able to execute arbitrary code subject to the
user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9f113fa");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Netop Remote Control Guest 10.0 build 2011087 or greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NetOp Remote Control Client 9.5 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netop:remote_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("netop_remote_control_guest_installed.nasl");
  script_require_keys("SMB/Netop_Remote_Control_Guest/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

kb_base = "SMB/Netop_Remote_Control_Guest/";
port = get_kb_item("SMB/transport");

get_kb_item_or_exit(kb_base + "Installed");

version = get_kb_item_or_exit(kb_base + "Version");

if (ver_compare(ver:version, fix:'10.0.2011.87', strict:FALSE) == -1)
{
  if (report_verbosity > 0) 
  {
    version_ui = get_kb_item_or_exit(kb_base + "Version_UI");
    path = get_kb_item_or_exit(kb_base + "Path");
    report += '\n  Path              : '+path+
              '\n  Installed version : '+version_ui+ ' (' + version + ')' +
              '\n  Fixed version     : 10.0.11087 (10.0.2011.87)\n';
    security_hole(port:port, extra:report); 
  }
  else security_hole(port);
} 
else 
  audit(AUDIT_INST_VER_NOT_VULN, "Netop Remote Control Guest", version);

