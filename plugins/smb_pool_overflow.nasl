#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(48405);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/13 15:30:41 $");

 script_cve_id("CVE-2010-2550", "CVE-2010-2551", "CVE-2010-2552");
 script_bugtraq_id(42224, 42263, 42267);
 script_osvdb_id(66974, 66975, 66976);
 script_xref(name:"EDB-ID", value:"14607");
 script_xref(name:"MSFT", value:"MS10-054");

 script_name(english:"MS10-054: Vulnerabilities in SMB Server Could Allow Remote Code Execution (982214) (remote check)");
 script_summary(english:"Checks response to a Trans2 Query FS Attribute query");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to execute arbitrary code on the remote Windows host
due to flaws in its SMB implementation."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is affected by several vulnerabilities in the SMB
server that may allow an attacker to execute arbitrary code or perform
a denial of service against the remote host.  These vulnerabilities
depend on access to a shared drive, but do not necessarily require
credentials."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-054");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for Windows XP, Vista, 2008, 7,
and 2008 R2."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("samba_detect.nasl", "smb_accessible_shares.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/accessible_shares/1");
 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("byte_func.inc");
include("misc_func.inc");


if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

#
# added @max_dcount from the original smb_trans2 in smb_func.inc
#
# return server response, starting with the smb header
#
function my_smb_trans2(param, data, max_dcount, max_pcount, command)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_TRANSACTION2,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = raw_byte (b:0);

 p_offset = 66;
 d_offset = p_offset + strlen (param);

 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_word (w:plen)   +   # total parameter count
	      raw_word (w:dlen)         +   # total data count
	      raw_word (w:max_pcount)   +   # Max parameter count
	      raw_word (w:max_dcount)   +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
        raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)         +   # Parameter count
	      raw_word (w:p_offset)     +   # Parameter offset
	      raw_word (w:dlen)         +   # Data count
	      raw_word (w:d_offset)     +   # Data offset
	      raw_byte (b:1)            +   # Setup count
	      raw_byte (b:0)            +   # Reserved
              raw_word (w:command);         # command

 parameters = smb_parameters (data:parameters);

 dat = pad +
       param +
       data;

 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 return smb_sendrecv (data:packet);

}



host    = get_host_ip();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# init a smb session
session_init(socket:soc, hostname:host);

# protocol negotiate and authentication
if ( smb_login(login:login,password:pass,domain:domain) != 1 )
{
  close(soc);
  audit(AUDIT_FN_FAIL, "smb_login");
}
session_set_authenticated();

#
# get an accessible share
#
accessible_shares = get_kb_item_or_exit("SMB/accessible_shares/1");
shares = get_kb_list("SMB/shares");
if (isnull(shares)) exit(1, "The 'SMB/shares' KB items are missing.");

shares = make_list(shares);

foreach share (shares)
{
  if (share != "IPC$" && share >< accessible_shares) break;
  else share = NULL;
}

if (isnull(share)) exit(1, "No accessible shares were found.");

# connect to the share
if (! smb_tree_connect_and_x(share:share))
{
  close(soc);
  exit(1, "Failed to connect to network share '" + share + "'.");
}


# send Trans2 Query FS Attribute query
fs_query = 3;                   # file system query
parameters = raw_word(w:0x105); # file system Attribute Query

res = my_smb_trans2(param:parameters, data: NULL, max_dcount:0x0F, max_pcount:0, command: fs_query);
close(soc);

if (! res)
{
  exit(1, "No response from the server to an SMB Trans2 request.");
}

# get status code
code = get_header_nt_error_code(header:res);
if (code == STATUS_BUFFER_OVERFLOW)
{
  security_hole(port:port);
}
else if( code == STATUS_INFO_LENGTH_MISMATCH)
{
  audit(AUDIT_HOST_NOT, "affected");
}
else
{
  exit(1, "Unexpected status code (" + code + ").");
}
