#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10380);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");

 script_cve_id("CVE-2012-6392");
 script_bugtraq_id(57221);
 script_osvdb_id(89112);
 script_xref(name:"CISCO-BUG-ID", value:"CSCuc79779");
 script_xref(name:"IAVA", value:"2013-A-0019");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20130109-lms");

 script_name(english:"rsh Unauthenticated Access (via finger Information)");
 script_summary(english:"attempts to log in using rsh");

 script_set_attribute(attribute:"synopsis", value:"It was possible to log on this machine without password.");
 script_set_attribute(attribute:"description", value:
"Using common usernames as well as the usernames reported by 'finger',
Nessus was able to log in through rsh.  Either the accounts are not
protected by passwords or the ~/.rhosts files are not configured
properly. 

This vulnerability is confirmed to exist in Cisco Prime LAN Management
Solution, but could be present on any host that is not securely
configured.");
 script_set_attribute(attribute:"solution", value:
"If the remote host is a Cisco Prime LAN Management Solution virtual
appliance, apply the relevant patch referenced in Cisco security
advisory cisco-sa-20130109-lms. 

Otherwise, remove the .rhosts files or set a password on the impacted
accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "finger.nasl", "rsh.nasl");
 script_require_ports("Services/rsh", 514);
 script_require_keys("rsh/active");
 script_exclude_keys("global_settings/supplied_logins_only");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var tested, report;
tested = make_array();

report = '';

function login(rsh_port, name)
{
 local_var a, data, s1, s2, soc;

 if (tested[name]) return;
 tested[name] = 1;

 soc = open_priv_sock_tcp(dport:rsh_port);
 if (! soc) return;

  s1 = raw_string(0);
  s2 = name + raw_string(0) + name + raw_string(0) + "id" + raw_string(0);
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  a = recv(socket:soc, length:1024);
  a += recv(socket:soc, length:1024);
  if("uid=" >< a )
  {
   a = str_replace(find:raw_string(0), replace:"", string:a);
   report = strcat(report,
"It was possible to log into this host using the account '", name , "'.
Here is the output of the 'id' command :
", a, '\n\n');
  }
  close(soc);
}

function test_finger(rsh_port, finger_port)
{
 local_var	finger, r, s;
 if (! get_port_state(finger_port)) return;
 finger = open_sock_tcp(finger_port);
 if (! finger) return;
 send(socket:finger, data: '\r\n');
 r = recv_line(socket:finger, length:1024);
 if (! r) { close(finger); return; }
 r = recv_line(socket:finger, length:1024);
 while(r)
 {
  s = strstr(r," ");
  r = r - s;
  login(name:r, rsh_port:rsh_port);
  r = recv_line(socket:finger, length:1024);
 }
 close(finger);
}

rsh_port = get_kb_item("Services/rsh");
if (! rsh_port) rsh_port = 514;
if (! get_port_state(rsh_port)) audit(AUDIT_PORT_CLOSED, rsh_port);

login(rsh_port:rsh_port, name:"root");

#
# these will most likely find backdoor rather
# than real unconfigured systems
#
login(rsh_port:rsh_port, name:"toor");
login(rsh_port:rsh_port, name:"bin");
login(rsh_port:rsh_port, name:"daemon");
login(rsh_port:rsh_port, name:"operator");
login(rsh_port:rsh_port, name:"nobody");
login(rsh_port:rsh_port, name:"adm");
login(rsh_port:rsh_port, name:"ftp");
login(rsh_port:rsh_port, name:"postgres");
login(rsh_port:rsh_port, name:"gdm");

finger_port = get_kb_item("Services/finger");
if(!finger_port)finger_port = 79;

test_finger(rsh_port: rsh_port, finger_port: finger_port);

if (report) security_hole(port: rsh_port, extra: report);
