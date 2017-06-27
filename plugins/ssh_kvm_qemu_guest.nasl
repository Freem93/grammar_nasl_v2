#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56300);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/11/21 21:29:12 $");

  script_name(english:"KVM / QEMU Guest Detection (credentialed check)");
  script_summary(english:"Determines if the remote OS is running in a KVM virtual machine");

  script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be a KVM / QEMU virtual machine.");
 script_set_attribute(attribute:"description", value:
"According to its model name, the machine is running on a QEMU virtual
processor.");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration agrees with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl", "ssh_proc_cpuinfo.nasl");
 script_require_keys('Host/uname');
 exit(0);
}

include('global_settings.inc');

cpu = NULL;

kb = get_kb_item('Host/proc/cpu_model_name');
if ('QEMU Virtual CPU' >< kb) cpu = kb;
else
{
  uname = get_kb_item('Host/uname');
  m = eregmatch(string: uname, pattern: '[ \t](QEMU Virtual CPU version [0-9.]+)[ \t]');
  if (m) cpu = m[1];
}

if (!isnull(cpu))
{
  set_kb_item(name:"Host/VM/QEMU", value:TRUE);    

  if (report_verbosity > 0) security_note(port: 0, extra: '\nThe virtual CPU model is : '+ cpu + '\n');
  else security_note(0);
  exit(0);
}
else exit(0, "The host does not appear to be a KVM / QEMU guest.");
