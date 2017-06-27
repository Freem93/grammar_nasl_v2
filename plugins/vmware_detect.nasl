#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20094);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/10/16 17:51:58 $");
 
 script_name(english:"VMware Virtual Machine Detection");
 script_summary(english:"Determines if the remote host is VMware.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a VMware virtual machine.");
 script_set_attribute(attribute:"description", value:
"According to the MAC address of its network adapter, the remote host
is a VMware virtual machine.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:
"Since it is physically accessible through the network, ensure that its
configuration matches your organization's security policy.");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/27");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

 script_dependencies("report_hw_macs.nasl");
 script_require_keys("Host/mac_addrs");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ether = get_kb_item_or_exit("Host/mac_addrs");

# -> http://standards.ieee.org/regauth/oui/index.shtml
if (egrep(pattern:"^00:(0c:29|05:69|50:56)", string:ether, icase:TRUE))
{
  set_kb_item(name: "Host/VM/vmware", value: TRUE);
  report = NULL;
  if(report_verbosity > 0)
  {
    report = '\nThe remote host is a VMware virtual machine.\n';
  }
  security_note(port:0, extra:report);
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, "a VMWare virtual machine");
}
