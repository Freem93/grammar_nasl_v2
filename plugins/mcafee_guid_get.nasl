#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(77477);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2014/11/05 16:29:08 $");

 script_name(english:"Microsoft Windows SMB Registry : McAfee EPO GUID");
 script_summary(english:"Determines the remote EPO GUID");

 script_set_attribute(attribute:"synopsis", value:"The remote system is managed by McAfee EPO.");
 script_set_attribute(attribute:"description", value:
"By reading the registry key HKLM\\SOFTWARE\\Network
Associates\\ePolicy Orchestrator\\Agent, it was possible to determine
that the remote Windows system is managed by McAfee EPO.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

access = get_kb_item_or_exit("SMB/Registry/Enumerated");

#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

regkeys = make_list(
  "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent\AgentGUID",
  "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent\GUID"
);

foreach key (regkeys)
{
  value = get_registry_value(handle:hklm, item:key);
  if (!isnull(value)) break;
}
RegCloseKey(handle:hklm);
close_registry();

if (!isnull(value))
{
  if (defined_func('report_xml_tag')) report_xml_tag(tag:"mcafee-epo-guid", value:value);
  port = kb_smb_transport();
  security_note(port:port, extra:'The remote host is designated by the following McAfee EPO GUID : ' + value);
}
