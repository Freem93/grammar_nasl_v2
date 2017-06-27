#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11993);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2012/02/17 13:05:00 $");

 script_name(english:"Yahoo Messenger Detection");
 script_summary(english:"Checks remotely for Yahoo Messenger");

 script_set_attribute(attribute:"synopsis", value:
"There is an instant messaging client installed on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"Yahoo Messenger is running on this machine and listening on this port. 
It allows a user to chat and share files with remote entities.");
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this program is in agreement with your
organization's security policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:yahoo:messenger");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("find_service2.nasl");
 script_require_ports(5101);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");


port = 5101;
if (!get_port_state(port))  exit(0);
if (!service_is_unknown(port:port)) exit(0);

# thanks to ethereal (www.ethereal.org) and the guys at
# http://libyahoo2.sourceforge.net/
# there was scant else on this protocol

# successful nudge...
# 59 4D 53 47 00 0B 00 00 00 35 00 4D 00 00 00 00  YMSG.....5.M....
# 8A 6B 3B E9 34 C0 80 66 66 66 66 66 66 66 C0 80  .k;.4..fffffff..
# 35 C0 80 66 30 30 66 30 30 64 69 6B 61 74 6F 72  5..f00f00dikator
# C0 80 31 33 C0 80 35 C0 80 34 39 C0 80 50 45 45  ..13..5..49..PEE
# 52 54 4F 50 45 45 52 C0 80                       RTOPEER..


# 20 bytes of Yahoo 'header' info
init = string("YMSG");
version = raw_string(0x00, 0x0b, 0x00, 0x00);
packet_len = raw_string(0x00, 0x00);   # just a placeholder...we'll fill in later 
service = raw_string(0x00, 0x4D);
status = raw_string(0x00, 0x00, 0x00, 0x00);
sessionID = raw_string(0x8A, 0x6B, 0x3B, 0xE9);


# start Yahoo data section
four = raw_string(0x34, 0xC0, 0x80);
sourceID = string(crap(length:10));
tieoff = raw_string(0xC0, 0x80);
five = raw_string(0x35, 0xC0, 0x80);
destID = string(crap(length:10));
thirteen = raw_string(0x31, 0x33, 0xC0, 0x80);
fortynine = raw_string(0x34, 0x39, 0xC0, 0x80);
ptwop = string("PEERTOPEER");

pseudo = strlen(init + version + packet_len + service + status + sessionID + four + sourceID + tieoff + five + destID + tieoff + thirteen + five + fortynine + ptwop + tieoff);

truelen = pseudo - 20;           
packhi = truelen / 255;
packlo = truelen % 255;
packet_len = raw_string(packhi, packlo);


packit = init + version + packet_len + service + status + sessionID + four + sourceID + tieoff +  five + destID + tieoff + thirteen + five + fortynine + ptwop + tieoff;



soc = open_sock_tcp(port);

if (soc) {
    send(socket:soc, data:packit);
    r = recv(socket:soc, length:128, timeout:3);
    if (r) {
        if (egrep(string:r, pattern:"^YMSG.*")) {
		set_kb_item(name:"Services/yahoo_messenger", value: port);
		security_note(port);
		}
        #display(r);
        exit(0);
    }
    close(soc);
} 
