#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(73125);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2014/03/21 00:23:59 $");

 script_name(english:"NAT-PMP Detection (local network)");
 script_summary(english:"NAT-PMP detection");

 script_set_attribute(attribute:"synopsis", value:"It is possible to create mappings to the local network.");
 script_set_attribute(attribute:"description", value:
"The remote device has the NAT-PMP protocol enabled.  This protocol
allows any application on the local subnet to request port mappings from
the outside to the inside. 

Make sure the use of this service is done in accordance to your security
policy.  Letting any application create dynamic mappings is usually not
recommended.");
 script_set_attribute(attribute:"solution", value:"Filter incoming traffic to UDP port 5351.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("nat_pmp_remote.nasl");
 script_require_keys("Services/udp/nat-pmp");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Services/udp/nat-pmp");
public_ip = get_kb_item_or_exit("nat-pmp/" + port + "/public-ip");

if ( !islocalnet() ) exit(0, "The target is not on the local network.");

security_note(port:port, proto:'udp', extra:'According to the remote service, the public IP address is :\n\n' + public_ip);
