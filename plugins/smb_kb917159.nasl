#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22034);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/10/07 15:36:47 $");

 script_cve_id("CVE-2006-1314", "CVE-2006-1315");
 script_bugtraq_id(18863, 18891);
 script_osvdb_id(27154, 27155);
 script_xref(name:"TRA", value:"TRA-2006-01");
 script_xref(name:"MSFT", value:"MS06-035");

 script_name(english:"MS06-035: Vulnerability in Server Service Could Allow Remote Code Execution (917159) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 917159");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
'Server' service.");
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to heap overflow in the 'Server' service
that may allow an attacker to execute arbitrary code on the remote
host with 'SYSTEM' privileges.

In addition to this, the remote host is also affected by an
information disclosure vulnerability in SMB that may allow an attacker
to obtain portions of the memory of the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-035");
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2006-01");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139, 445);
 exit(0);
}

#

include ("smb_func.inc");

function smb_get_error_code (data)
{
 local_var header, flags2, code;

 # Some checks in the header first
 header = get_smb_header (smbblob:data);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
 }
 else
 {
   code = get_header_dos_error_code (header:header);
 }

 return code;
}


function smb_trans_and_x2 (extra_parameters, transname, param, data, max_pcount)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen, pad2, socket;

 pad = pad2 = NULL;
 if (session_is_unicode () == 1)
   pad = raw_byte (b:0);
 else
   pad2 = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_TRANSACTION,
                      Status: nt_status (Status: STATUS_SUCCESS));

 trans = cstring (string:transname);

 p_offset = 66 + strlen(trans) + strlen (extra_parameters);
 d_offset = p_offset + strlen (param);

 plen = strlen(param);
 dlen = strlen(data);
 elen = strlen(extra_parameters);

 parameters = raw_word (w:plen)            +   # total parameter count
	      raw_word (w:dlen) +   # total data count
	      raw_word (w:max_pcount)            +   # Max parameter count
	      raw_word (w:0xFFFF)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)            +   # Parameter count
	      raw_word (w:p_offset)           +   # Parameter offset
	      raw_word (w:dlen) +   # Data count
	      raw_word (w:d_offset)           +   # Data offset
	      raw_byte (b:elen/2)            +   # Setup count
	      raw_byte (b:0);               # Reserved

 parameters += extra_parameters;

 parameters = smb_parameters (data:parameters);

 dat = pad +
       trans +
       pad2 +
       raw_word (w:0) +
       param +
       data;

 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;

 return smb_get_error_code (data:ret);
}


###########################
#        Main code        #
###########################

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name = kb_smb_name ();
port = kb_smb_transport ();

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

data = raw_word (w:1) +
       raw_word (w:1) +
       raw_word (w:1) ;

code = smb_trans_and_x2 (extra_parameters:data, transname:string("\\MAILSLOT\\NESSUS", rand()) , param:NULL, data:NULL, max_pcount:0);
if (!isnull(code))
{
 if (code == STATUS_OBJECT_NAME_NOT_FOUND)
   security_hole(port);
}

NetUseDel();
