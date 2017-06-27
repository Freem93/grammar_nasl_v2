#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20175);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/12/15 20:54:56 $");

 script_name(english:"VERITAS Backup Agent Detection");
 script_summary(english:"Detects VERITAS Backup Agent");

 script_set_attribute(attribute:"synopsis", value:
"A backup agent is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Backup Agent that uses the Network Data
Management Protocol (NDMP).");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_require_ports('Services/unknown', 10000);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");
include("audit.inc");

global_var __stream, __stream_length, __stream_pos, __stream_error;
global_var soc, port, ndmp_cid, info;

NDMP_MESSAGE_REQUEST = 0;
NDMP_MESSAGE_REPLY   = 1;
NDMP_CONFIG_GET_HOST_INFO     = 0x100;
NDMP_CONFIG_GET_SERVER_INFO   = 0x108;
NDMP_NOTIFY_CONNECTION_STATUS = 0x502;
NDMP_CONFIG_GET_AGENT_PROPERTIES = 0xF31B;

info = NULL;

function xdr_error_audit()
{
  __rpc_stream_error = TRUE;
  if (soc) close(soc);
  if (!isnull(info) && info != '')
  {
    info += '\n** Corrupted or incomplete data detected. **\n';
    security_report_v4(port:port, extra:info, severity:SECURITY_NOTE);
    exit(0);
  }
  audit(AUDIT_RESP_BAD, port);
}

function xdr_getdword_wrapper()
{
  local_var d;
  d = xdr_getdword();
  if (isnull(d))
    xdr_error_audit();
  return d;
}

function xdr_getopaquestring()
{
 local_var s, d, tmps, i, len;

 d = xdr_getdword_wrapper(); ## the length header field

 if (!d || (__rpc_stream_pos + d) > __rpc_stream_length)
 {
   xdr_error_audit();
 }

 tmps = substr(__rpc_stream, __rpc_stream_pos, __rpc_stream_pos+d-1);
 __rpc_stream_pos += d;

 if (d % 4)
  __rpc_stream_pos += 4 - (d%4);

 s = NULL;
 len = strlen(tmps);
 for (i=0; i < len; i++)
 {
  if (tmps[i] == '\0')
    return s;
 else
   s += tmps[i];
 }

 return s;
}


function ndmp_packet (code, data)
{
 local_var pack;

 pack =
  mkdword (ndmp_cid)               + # sequence
  mkdword (0)                      + # time_stamp
  mkdword (NDMP_MESSAGE_REQUEST)   + # message type
  mkdword (code)                   + # message code
  mkdword (0)                      + # reply sequence
  mkdword (0)                      + # Error code
  data;

 return mkdword(strlen(pack) | 0x80000000) + pack;
}


function ndmp_recv (socket, sent_code) 
{
 local_var len, data, header, peek, peeksize, peekdata;
 peeksize = 14;

 data = recv (socket:socket, length:4, min:4);
 if (strlen(data) < 4)
   xdr_error_audit(); # return NULL;
 len = getword (blob:data, pos:2);
 peekdata = recv (socket:socket, min:peeksize, length:peeksize);
 peek = getword (blob:peekdata, pos:10);
 data = peekdata;
 ## Check to see if we're matching protocol so far
 if (isnull(sent_code))
 { # if this is the first transmission
   if (peek != NDMP_MESSAGE_REQUEST) xdr_error_audit();
 }
 else
 { # if this is a reply transmission
   if (peek != NDMP_MESSAGE_REPLY) xdr_error_audit();
 }
 peekdata = recv (socket:socket, min:4, length:4);
 peeksize += 4;
 peek = getword(blob:peekdata, pos:0);
 if (!isnull(sent_code) && peek != sent_code)
   xdr_error_audit();
 data += peekdata;
 data += recv (socket:socket, min:len-peeksize, length:len-peeksize);

 if (strlen(data) != len)
   xdr_error_audit(); # return NULL;

 if (strlen(data) < 24)
   xdr_error_audit(); # return NULL;

 header = NULL;
 register_stream(s:data);

 header[0] = xdr_getdword_wrapper();
 header[1] = xdr_getdword_wrapper();
 header[2] = xdr_getdword_wrapper(); # expected to be NDMP_MESSAGE_REPLY
 header[3] = xdr_getdword_wrapper();
 header[4] = xdr_getdword_wrapper();
 header[5] = xdr_getdword_wrapper();

 if (strlen(data) > 24)
   header[6] = substr (data, 24, strlen(data)-1);
 else
   header[6] = NULL;

 return header;
}

function ndmp_sendrecv(socket, code, data)
{
 local_var ret;

 data = ndmp_packet(code:code, data:data);

 send(socket:socket, data:data);
 ret = ndmp_recv(socket:socket, sent_code:code);
 
 if (ret[5] != 0 || ret[3] != code || ret[2] != NDMP_MESSAGE_REPLY)
   return NULL;

 return ret[6];
}

# Main code

port = get_unknown_svc(10000);
if (!port) audit(AUDIT_SVC_KNOWN);

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp (port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = ndmp_recv(socket:soc);
if (isnull(req))
  xdr_error_audit();

if (req[2] != NDMP_MESSAGE_REQUEST || req[3] != NDMP_NOTIFY_CONNECTION_STATUS)
  xdr_error_audit();


ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_SERVER_INFO, data:NULL);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword_wrapper();
 vendor_name     = xdr_getopaquestring();
 product_name    = xdr_getopaquestring();
 revision_number = xdr_getopaquestring();

 info +=  'NDMP Server Info:\n\n'+
          'Vendor   : ' + vendor_name +      '\n'+
          'Product  : ' + product_name +     '\n'+
          'Revision : ' + revision_number +  '\n\n';
}

ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_HOST_INFO, data:NULL);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword_wrapper();
 hostname = xdr_getopaquestring();
 os_type  = xdr_getopaquestring();
 os_vers  = xdr_getopaquestring();
 hostid   = xdr_getopaquestring();

 set_kb_item(name:'Host/Veritas/BackupExecAgent/OS_Type', value:os_type);
 set_kb_item(name:'Host/Veritas/BackupExecAgent/OS_Version', value:os_vers);

 info += 'NDMP Host Info:\n\n'+
         '  Hostname   : '+ hostname + '\n'+
         '  OS type    : '+ os_type  + '\n'+
         '  OS version : '+ os_vers  + '\n'+
         '  HostID     : '+ hostid   + '\n\n';
}

data = xdr_string('nessus');

ret = ndmp_sendrecv(socket:soc, code:NDMP_CONFIG_GET_AGENT_PROPERTIES, data:data);

if (!isnull(ret))
{
 register_stream(s:ret);

 error = xdr_getdword_wrapper();

 u1 = xdr_getdword_wrapper();
 u2 = xdr_getdword_wrapper();
 u3 = xdr_getdword_wrapper();

 v1 = xdr_getdword_wrapper();
 v2 = xdr_getdword_wrapper();
 v3 = xdr_getdword_wrapper();
 v4 = xdr_getdword_wrapper();

 version = v1+'.'+v2+'.'+v3+'.'+v4;
 set_kb_item(name:'Veritas/BackupExecAgent/Version', value:version);

 info += 'NDMP Agent Info:\n\n'+
         '  Version : ' + version + '\n\n';
}

if (soc) close(soc);

security_report_v4(port:port, extra:info, severity:SECURITY_NOTE);
register_service(port:port, proto:'veritas-backup-agent');
