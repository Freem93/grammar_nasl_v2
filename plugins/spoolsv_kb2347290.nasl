#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49286);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2010-2729");
  script_bugtraq_id(43073);
  script_osvdb_id(67988);
  script_xref(name:"IAVA", value:"2010-A-0124");
  script_xref(name:"MSFT", value:"MS10-061");

  script_name(english:"MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) (EMERALDTHREAD) (uncredentialed check)");
  script_summary(english:"Test vulnerability of Spoolsv.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
Spooler service.");
  script_set_attribute(attribute:"description", value:
"The version of the Print Spooler service on the remote Windows host is
affected by a service impersonation vulnerability that allows an
unauthenticated, remote attacker to execute arbitrary code on a
Windows XP system to escalate privileges on all other supported
Windows systems.

EMERALDTHREAD is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-061");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("byte_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows 5.1" >!< os ) exit(0, "The OS is not Windows XP.");

# create a comformant and varying marshalled string
function ndr_string(string)
{
  if(isnull(string))
  {
    return NULL;
  }
  return  mkdword(strlen(string) + 1) + # max count
          mkdword(0) +                  # offset
          mkdword(strlen(string) + 1) + # actual count
          cstring(string:string);       # the string in unicode
}

function get_rpc_return_status(data)
{
  if(strlen(data) >= 4)
    return get_dword (blob:data, pos:(strlen(data)-4));
  else
    return NULL;
}

PRINTER_ENUM_LOCAL   = 0x00000002;
PRINTER_ENUM_SHARED  = 0x00000020;
PRINTER_ENUM_NETWORK = 0x00000040;
PRINTER_ENUM_NAME    = 0x00000008;
function enum_printer_req()
{

	return raw_dword(d:(PRINTER_ENUM_LOCAL | PRINTER_ENUM_SHARED)) +
	raw_dword(d:0) +
	raw_dword(d:1) +
	raw_dword(d:0x2000c) +
	raw_dword(d:_FCT_ANON_ARGS[0]) +
	crap(length:_FCT_ANON_ARGS[0], data:'\x00') +
	raw_dword(d:_FCT_ANON_ARGS[0]);
}


function get_printers(fid)
{
  local_var i, res, status, needed_sz, bufsz, nprinters, printer, printers;
  local_var name_offset,entry_offset, entry_size, STRUCT_PRINT_INFO1;

  res = dce_rpc_pipe_request(fid:fid, code:0x00, data:enum_printer_req(0));
  if(isnull(res) || (strlen(res) < 4))
  {
    return NULL;
  }
  res = dce_rpc_parse_response(data:res);

  status = get_rpc_return_status(data:res);
  if(status != ERROR_INSUFFICIENT_BUFFER)
  {
    return NULL;
  }

  needed_sz = get_dword(blob:res, pos:8);

  if(!needed_sz || (needed_sz > 1024 * 1024))
  {
    return NULL;
  }

  res = dce_rpc_pipe_request(fid:fid, code:0x00, data:enum_printer_req(needed_sz));

  if(isnull(res))
  {
    return NULL;
  }

  res = dce_rpc_parse_response(data:res);
  status = get_rpc_return_status(data:res);
  if(status != ERROR_SUCCESS)
  {
    return NULL;
  }

  bufsz = get_dword(blob:res, pos:4);
  nprinters = get_dword(blob:res, pos:(strlen(res)-4 -4));

  # sanity check
  if(nprinters * 16 > bufsz)  # each printer has 16-byte memta struct
  {
    return NULL;
  }

  STRUCT_PRINT_INFO1 = substr(res, 8, 8 + needed_sz);

  entry_offset = 0;
  entry_size   = 16;
  for (i = 0; i < nprinters; i++)
  {
    name_offset = get_dword(blob:STRUCT_PRINT_INFO1, pos:entry_offset + 8);
    printer = get_string(blob:STRUCT_PRINT_INFO1, pos: entry_offset + name_offset, _type:1);
    entry_offset += entry_size;
    printers[i] = printer;
  }

  return printers;
}

function open_printer(fid, printer)
{
  local_var client, user, data, res, status, padlen;

  client = kb_smb_name();
  user = "nessus";
  data =  mkdword(0x00020000) +             # printe name ref id
          ndr_string(string:printer);
  padlen = strlen(data) % 4;
  data += mkpad(padlen) +                   # params are 32bit-aligned
          mkdword(0)  +                     # printer datatype ref id
          mkdword(0)  +                     # device mode ctr size
          mkdword(0)  +                     # device mode
          mkdword(0)  +                     # access right
          mkdword(1)  +                     # info level
          mkdword(1)  +                     # user level container ref id
          mkdword(0x00020004) +             # info level
          mkdword(0x1c) +                   # size
          mkdword(0x00020008) +             # client ref id
          mkdword(0x0002000c) +             # user ref id
          mkdword(6002) +                   # build
          mkdword(3) + mkdword(0) +         # major and minor
          mkdword(0) +                      # processor
          ndr_string(string:client);        # client name
  padlen = strlen(data) % 4;
  data += mkpad(padlen) +
          ndr_string(string:user);          # user name

  res = dce_rpc_pipe_request (fid:fid, code:69, data:data);
  if (isnull(res))
  {
    return NULL;
  }
  res = dce_rpc_parse_response (fid:fid, data:res);
  status = get_rpc_return_status(data:res);
  if(status != ERROR_SUCCESS || strlen(res) != 0x18)
  {
    return NULL;
  }

  return substr(res,0, 0x13);
}

function send_print_job(fid, hprinter, outfile)
{
  local_var res, data,ret;

  data = hprinter +
         mkdword(1) +                   # doc info container info level
         mkdword(1) +                   # doc info level
         mkdword(0x00020000) +          # Doc info ref id
         mkdword(0) +                   # doc name ref id, default doc name
         mkdword(0x20000001) +          # output file ref id
         mkdword(0)          +          # data type ref id
         ndr_string(string:outfile);    # output file name

  res = dce_rpc_pipe_request (fid:fid, code:17, data:data);

  if(isnull(res))
  {
    return NULL;
  }

  res = dce_rpc_parse_response (fid:fid, data:res);

  if(strlen(res) < 8)
  {
    return NULL;
  }
  ret['job_id'] = get_dword(blob:res, pos:(strlen(res)-4 -4));
  ret['status'] = get_rpc_return_status(data:res);

  return ret;
}

JOB_CONTROL_CANCEL  = 0x00000003;
function cancel_print_job(fid, hprinter, jid)
{
  local_var res, data;

  data = hprinter       +
         mkdword(jid)   +
         mkdword(0)     +
         mkdword(JOB_CONTROL_CANCEL);


  res = dce_rpc_pipe_request (fid:fid, code:2, data:data);

  if(isnull(res))
  {
    return NULL;
  }

  res = dce_rpc_parse_response (fid:fid, data:res);

  return get_rpc_return_status(data:res);
}

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0, "Port "+port+" is not open.");
soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");


name	= kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
session_init(socket:soc, hostname:name);

if(isnull(login)) login = "guest";

if (! NetUseAdd(login:login,password:pass,share:"IPC$"))
{
  close(soc);
  exit(1, "Can't connect to IPC$ share.");
}

# open spooler pipe
fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
if (isnull (fid))
{
  NetUseDel(close:TRUE);
  exit(1,"Failed to connect to spoolss pipe.");
}

# enum printers
printers = get_printers(fid:fid);
if(! printers)
{
  NetUseDel(close:TRUE);
  exit(1,"No shared printers found.");
}

# open a printer
foreach printer (printers)
{
  hprinter = open_printer(fid:fid, printer:printer);
  if(hprinter) break;
}

if( isnull(hprinter))
{
  NetUseDel(close:TRUE);
  exit(1,"Failed to open a printer.");
}

# send a job with an invalid output file name
ret = send_print_job(fid:fid,hprinter:hprinter, outfile:":");
if( isnull(ret))
{
  NetUseDel(close:TRUE);
  exit(1, "send_print_job() failed.");
}

status = ret['status'];
job_id = ret['job_id'];

if(status == ERROR_SUCCESS)
{

  # a print job was queued, so need to cancel it
  cancel_attempts = 0;
  repeat
  {
    status = cancel_print_job(fid:fid, hprinter: hprinter, jid: job_id);
    cancel_attempts++;
  }until(status == ERROR_SUCCESS || cancel_attempts > 3);

  NetUseDel(close:TRUE);
  exit(0, "The host is not affected.");
}
else
{
  NetUseDel(close:TRUE);
  if(status == ERROR_PRINT_CANCELLED)
  {
    security_hole(port:port);
  }
  else
  {
    exit(1,"Unexpected StartDocPrinter() return status (" + status + ").");
  }
}










