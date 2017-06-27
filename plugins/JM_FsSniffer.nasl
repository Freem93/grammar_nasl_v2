#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 

# Changes by Tenable:
# - Revised plugin title (12/28/10)

include("compat.inc");

if(description)
{

script_id(11854);
script_version ("$Revision: 1.11 $");
script_name(english:"FsSniffer Backdoor Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running FsSniffer on this port.

FsSniffer is backdoor which allows an intruder to steal
PoP3/FTP and other passwords you use on your system.

An attacker may use it to steal your passwords." );
 script_set_attribute(attribute:"solution", value:
"See http://www.nessus.org/u?10e4148e for details on removal" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/29");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

script_summary(english:"Determines the presence of FsSniffer");

script_category(ACT_GATHER_INFO);

script_copyright(english:"This script is Copyright (C) 2003-2013 J.Mlodzianowski");
script_family(english:"Backdoors");
script_dependencie("find_service2.nasl");
script_require_ports("Services/RemoteNC");
exit(0);
}


#
# The code starts here
#

port =  get_kb_item("Services/RemoteNC");
if(port)security_hole(port);
