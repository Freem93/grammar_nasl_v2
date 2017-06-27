#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(47556);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
   "CVE-2010-0020",
   "CVE-2010-0021",
   "CVE-2010-0022",
   "CVE-2010-0231"
 );
 script_bugtraq_id(38049, 38051, 38054, 38085);
 script_osvdb_id(62253, 62254, 62255, 62256);
 script_xref(name:"MSFT", value:"MS10-012");

 script_name(english:"MS10-012: Vulnerabilities in SMB Could Allow Remote Code Execution (971468) (uncredentialed check)");
 script_summary(english:"Remote check for MS10-012 (SMB vulnerabilities)");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to execute arbitrary code on the remote Windows host due
to flaws in its SMB implementation."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is affected by several vulnerabilities in the SMB
server that may allow an attacker to execute arbitrary code or perform a
denial of service against the remote host.

These vulnerabilities depend on access to a shared drive, but do not
necessarily require credentials."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-012");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(20, 94, 264, 310, 362);

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:windows:smbsvr");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl", "smb_accessible_shares.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/accessible_shares/1");
 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");


host    = get_host_ip();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#
# modified the original smb_trans2 in smb_func.inc
# return server response, starting with the smb header
#
function my_smb_trans2 (param, data, max_pcount, command)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_TRANSACTION2,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = raw_byte (b:0);

 p_offset = 66;
 d_offset = p_offset + strlen (param);

 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_word (w:plen)         +   # total parameter count
      raw_word (w:dlen)         +   # total data count
      raw_word (w:max_pcount)   +   # Max parameter count
      raw_word (w:1000)         +   # Max data count
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



if ( ! get_port_state(port) ) exit(0, "Port "+port+" is not open.");
soc = open_sock_tcp(port);
if ( ! soc )
{
  exit(1, "Failed to open a socket on port "+port+".");
}

# init a smb session
session_init(socket:soc, hostname:host);

# protocol negotiate and authentication
if ( smb_login(login:login,password:pass,domain:domain) != 1 )
{
  close(soc);
  exit(1, "smb_login() failed.");
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

# send a TRANS2 FIND_FIRST2 query
pattern = crap(data:"a", length:0x7c3);
cmd_find_first2 = 1;
parameters = raw_word (w:0x16)   + # Default search : include HIDDEN/SYSTEM/DIRECTORY
             raw_word (w:0xDFFF) + # Max buffer search count
             raw_word (w:6)      + # Close if EOS is reached / RESUME
             raw_word (w:260)    + # Default level of interest
             raw_dword (d:0)     + # Storage type
             cstring (string:pattern);

res = my_smb_trans2 (param:parameters, data:NULL, max_pcount:18, command:cmd_find_first2);

close(soc);

if (! res)
{
  exit(1, "No response from the server to an SMB Trans2 request.");
}

# get status code
code = get_header_nt_error_code(header:res);
if (code == STATUS_NO_SUCH_FILE)
{
  security_hole(port:port);
}
else if( code == STATUS_INVALID_PARAMETER)
{
  exit(0, "The host is not affected.");
}
else
{
  exit(1, "Unexpected status code (" + code + ").");
}
