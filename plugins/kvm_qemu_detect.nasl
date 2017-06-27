#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(56877);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2015/10/16 17:51:58 $");

 script_name(english:"KVM / QEMU Guest Detection (uncredentialed check)");
 script_summary(english:"Checks the MAC address.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a KVM / QEMU virtual machine.");
 script_set_attribute(attribute:"description", value:
"According to the MAC address of its network adapter, the remote host
is a KVM / QEMU virtual machine.");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration agrees with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/21");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

 script_dependencies("report_hw_macs.nasl");
 script_require_keys("Host/mac_addrs");

 exit(0);
}

ether = get_kb_item("Host/mac_addrs");
if (!ether) exit(0, "The host's ethernet address is unknown.");

# http://www.mail-archive.com/et-mgmt-tools@redhat.com/msg02715.html
if (egrep(pattern:"^(54:52|52:54):00", string:tolower(ether)))
{
  set_kb_item(name:"Host/VM/QEMU", value:TRUE);

  security_note(0);
  exit(0);
}
else exit(0, "The host does not appear to be a KVM / QEMU guest based on its MAC address.");
