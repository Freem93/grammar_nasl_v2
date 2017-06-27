#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27627);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/25 13:54:52 $");

  script_name(english:"HP OVCM/Radia Notify Daemon Detection");
  script_summary(english:"Sends a Notify request.");

 script_set_attribute(attribute:"synopsis", value:
"A remote control service is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote service is an HP OVCM/Radia Notify Daemon, a component
of an endpoint management solution. The presence of this service
typically indicates the host is a managed device.");
 # http://www8.hp.com/us/en/software-solutions/operations-manager-infrastructure-monitoring/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f63d88b");
 script_set_attribute(attribute:"see_also", value:"https://radia.accelerite.com/");
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3465);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("dump.inc");


function ntfy_req(rport, uid, pass, cmd)
{
  local_var req;

  req = string(rport) + mkbyte(0) +       # listening port on nessusd host
    uid + mkbyte(0) +                     # user (max 0x20 bytes)
    pass + mkbyte(0) +                    # pass (encrypted) (max 0x20 bytes)
    cmd + mkbyte(0);                      # command to launch (max 0x400 bytes)
  return req;
}

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(3465);
  if (!port) audit(AUDIT_SVC_KNOWN); 
}
else port = 3465;

if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);  

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port); 

#
# These credentials will cause an error response if the Notify 
# daemon is configured with username and/or password verification
# (the ZVRFYUID and ZVRFYPWD variables in the NTFYSEC.EDM file
# in IDMLIB (C:\Program Files\Hewlett-Packard\HPCA\Agent\Lib)) 
#
# If username/password verification is not enabled, the command 
# following the credentials is processed by the Notify Daemon. 
#
uid  = "U_" + SCRIPT_NAME;
pass = "P_" + SCRIPT_NAME;

#cmd = string(
#  "radskman ",
#    "sname=DISCOVER_INVENTORY,",
#    "dname=AUDIT,",
#    "startdir=SYSTEM,",
#    "rtimeout=7200,",
#    "port=3464,",
#    "ip=", this_host(), ",",
#    "cop=y,",
#    "mnt=y,",
#    "JOBID=N:79:80"
#);

# The Notify daemon will never able to execute this command as
# the command executable is not in the IDMSYS directory 
# (C:\Program Files\Hewlett-Packard\HPCA\Agent), so the daemon will
# send back an error message.
#
cmd = "CMD_" + SCRIPT_NAME;

# Send first probe with invalid uid length.
# The Notify daemon should close the connection because it violates
# the protocol.
req = ntfy_req(uid:crap(data:'A', length:0x28), pass:pass, cmd:cmd);
send(socket:soc, data:req);
res1 = recv(socket:soc, length:1024, min:128);
close(soc);

# Send second probe to solicit an error response
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port); 
req = ntfy_req(uid:uid, pass:pass, cmd:cmd);
send(socket:soc, data:req);
# The Notify daemon on Linux seems to take longer to respond
res = recv(socket:soc, length:1024, min:128, timeout:10);
close(soc);

if(isnull(res))
  audit(AUDIT_RESP_NOT, port, "a Notify request");

code = getbyte(blob:res, pos:0);

if (code == 1)
{
  # UID/Password verification enabled 
  if(stridx(res, "Invalid credentials specified.") == 1)
  {
    report_service(port:port, svc:"radexecd");
  }
  # UID/Password verification not enabled;
  # The Notify daemon attempts to run our command but fails 
  else if(stridx(res, "Unable to execute requested pgm.") == 1)
  {
    set_kb_item(name:"radexecd/" + port + "/noauth", value:TRUE); 
    report_service(port:port, svc:"radexecd");
  }
  # Unexpected; Could be a valid error response, investigate
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a Notify request:\n' + hexdump(ddata:res));
  }
}
# Extended Security is enabled; our credentials will fail the Extended
# Security check. The Notify daemon doesn't even attempt to execute
# our command, but it returns a single zero byte. 
else if (res == '\x00')
{
  # Use NULL response in the first probe to increase the reliability 
  # of detecting the Notify daemon configured with Extended Security. 
  if (isnull(res1))
  {
    report_service(port:port, svc:"radexecd");
  }
  #else
  # How likely another service respond with a single zero to our probe?
  # If so, silently drop it
}
# Unexpected response
else audit(AUDIT_RESP_BAD, port, 'a Notify request:\n' + hexdump(ddata:res));
  