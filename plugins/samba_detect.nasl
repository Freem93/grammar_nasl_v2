#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25240);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2013/01/07 14:19:58 $");

 script_name(english:"Samba Server Detection");
 script_summary(english:"Attempts to detect a Samba server");

 script_set_attribute(attribute:"synopsis", value:"An SMB server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Samba, a CIFS/SMB server for Linux and
Unix.");
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 
 script_dependencies("netbios_name_get.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445, "/tmp/settings");
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

function _RpcSpoolerInit ()
{
 local_var fid, data, type, error;

 fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
 if (isnull(fid))
   return FALSE;

 data = raw_word(w:0);

 data = dce_rpc_pipe_request (fid:fid, code:0x3f, data:data);
 smb_close (fid:fid);

 if (!data)
   return FALSE;

 if (strlen (data) < 28)
   return FALSE;
   
 type = get_byte (blob:data, pos:2);

 # Fault -> maybe samba
 if (type != 3)
   return FALSE;

 error = get_dword (blob:data, pos:24);
 if (error == 0x1c010002) # nca_op_rng_error
   return TRUE;

 return FALSE;
}


function _LsaDelete ()
{
 local_var fid, data, type, error;

 fid = bind_pipe (pipe:"\lsarpc", uuid:"12345778-1234-abcd-ef00-0123456789ab", vers:0);
 if (isnull(fid))
   return FALSE;

 data = NULL;

 data = dce_rpc_pipe_request (fid:fid, code:0x01, data:data);
 smb_close (fid:fid);

 if (!data)
   return FALSE;

 if (strlen (data) < 28)
   return FALSE;
   
 type = get_byte (blob:data, pos:2);

 # Fault -> maybe Samba
 if (type != 3)
   return FALSE;

 error = get_dword (blob:data, pos:24);
 if (error == 0x1c010002) # nca_op_rng_error
   return TRUE;

 return FALSE;
}


function register_samba(port)
{
 local_var kb, rep;

 kb = get_kb_item("SMB/samba");
 if (!kb)
 {
  set_kb_item(name:"SMB/samba", value:TRUE);  

  rep = 
"The remote host tries to hide its SMB server type by changing the MAC
address and the LAN manager name. 

However by sending several valid and invalid RPC requests it was
possible to fingerprint the remote SMB server as Samba.";
  security_note(port:port, extra: rep);
 }
 else
   security_note(port:port);

 replace_kb_item(name:"SMB/not_windows", value:TRUE);  
}


name	= kb_smb_name();
port	= kb_smb_transport();

if (get_kb_item("Host/scanned") && !get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);
r = NetUseAdd(share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, "IPC");

# 1) test the only Samba specific RPC service (unixinfo)
fid = bind_pipe (pipe:"\unixinfo", uuid:"9c54e310-a955-4885-bd31-78787147dfa6", vers:0);
if (!isnull (fid))
{
 smb_close(fid:fid);
 register_samba(port:port);
}
else
{
 # 2) test an undefined RPC function in Samba (SPOOLSS)
 ret = _RpcSpoolerInit();
 if (ret)
   register_samba(port:port);
 else
 {
  # 3) test an undefined RPC function in Samba (LSARPC)
  ret = _LsaDelete();
  if (ret)
    register_samba(port:port);
 }
}

NetUseDel();
