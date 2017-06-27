#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
#                            thanks to H.D.Moore
# 
#


include("compat.inc");

if(description)
{

 script_id(11855);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
# script_cve_id("CVE-2003-00002");
 name["english"] = "RemoteNC Backdoor Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running RemoteNC on this port

RemoteNC is a Backdoor which allows an intruder gain
remote control of your computer.

An attacker may use it to steal your passwords." );
 script_set_attribute(attribute:"solution", value:
"Visit the see_also URL for details on removal.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 # http://web.archive.org/web/20050418011325/http://www.rapter.net/jm2.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10e4148e");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Determines the presence of RemoteNC";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "JM_FsSniffer.nasl");
 exit(0);
}


#
# The code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/RemoteNC");
if (!port) exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = recv(socket:soc, min:1, length:30);
if(!r) exit(0);

if("RemoteNC Control Password:" >< r)  security_hole(port);
