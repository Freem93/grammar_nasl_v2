#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(48942);
 script_version ("$Revision: 1.5 $");
 script_cvs_date("$Date: 2016/11/16 17:11:02 $");

 script_name(english:"Microsoft Windows SMB Registry : OS Version and Processor Architecture");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the processor architecture, build lab
strings, and Windows OS version installed on the remote system.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine the the processor architecture, build lab
strings, and the Windows OS version installed on the remote system by
connecting to the remote registry with the supplied credentials.");

 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/31");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_summary(english:"Reports Windows OS version and processor architecture");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl","smb_reg_service_pack.nasl");
 script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild", "SMB/ARCH");
 exit(0);
}

port = get_kb_item("SMB/transport");

os_version = get_kb_item("SMB/WindowsVersion");
os_build   = get_kb_item("SMB/WindowsVersionBuild");
os_arch    = get_kb_item("SMB/ARCH");
os_labex   = get_kb_item("SMB/BuildLabEx");

os     = '';
report = '';

if(os_version)
{
  os = os_version;
  if(os_build)
   os += "." + os_build;

  report += 'Operating system version = ' + os + '\n';
}
if(os_arch)
  report += 'Architecture = '+ os_arch + '\n';

if(os_labex)
  report += 'Build lab extended = '+ os_labex + '\n';

# Always report
if (strlen(report) > 0)
 security_note(port:port,extra:report);
