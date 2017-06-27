#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(47800);
  script_version("$Revision: 1.3 $");
 
  script_name(english:"VirtualPC Virtual Machine detection (dmidecode)");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host seems to be a VirtualPC virtual machine." );
 script_set_attribute(attribute:"description", value:
"According to the DMI information, the remote host is a VirtualPC virtual
machine. 

Since it is physically accessible through the network, ensure that its
configuration matches your organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/19");
 script_cvs_date("$Date: 2011/03/21 15:27:34 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 
  script_summary(english:"Look for VirtualPC in dmidecode output");
   script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
  script_family(english:"General");
  script_dependencie("dmi_system_info.nasl");
  script_require_ports("DMI/System/ProductName");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

sys = get_kb_item_or_exit("DMI/System/ProductName");

if (chomp(sys) == "Microsoft Corporation")
{
  security_note(port: 0);
  set_kb_item(name: "Host/VM/virtualpc", value: TRUE);
}
