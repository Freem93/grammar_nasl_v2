#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53503);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/11/04 02:28:18 $");

  script_cve_id("CVE-2011-0661");
  script_bugtraq_id(47198);
  script_osvdb_id(71781);
  script_xref(name:"IAVA", value:"2011-A-0050");
  script_xref(name:"MSFT", value:"MS11-020");

  script_name(english:"MS11-020: Vulnerability in SMB Server Could Allow Remote Code Execution (2508429) (remote check)");
  script_summary(english:"Checks response to a SMB ReadAndX request with a large file offset");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to execute arbitrary code on the remote Windows host
due to flaws in its SMB implementation."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is affected by a vulnerability in the SMB server that
may allow an attacker to execute arbitrary code or perform a denial of
service against the remote host.  This vulnerability depends on access
to a Windows file share, but does not necessarily require credentials."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-020");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for Windows XP, Vista, 2008, 7,
and 2008 R2."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:windows:smbsvr");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("samba_detect.nasl", "smb_accessible_shares.nasl", "netbios_name_get.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/accessible_shares/1");
 script_require_ports(139, 445);
 exit(0);

}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

##
# added param <offset_high>  to the original smb_read_and_x in smb_cifs.inc
#
# @param fid          - file ID
# @param offset       - lower  32 bit of the file offset
# @param offset_high  - higher 32 bit of the file offset
# @param length       - number of bytes to read
#
# @return  server response, starting with the smb header
#          or NULL if an error occurred
##
function my_smb_read_and_x (fid, offset, offset_high, length)
{
 local_var header, parameters, data, packet, pad;

 if (session_is_smb2()) return smb2_read(fid:fid, offset:offset, length:length);

 header = smb_header (Command: SMB_COM_READ_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = raw_byte (b:0);

 parameters = raw_byte (b:255) +            # no further command
              raw_byte (b:0) +              # reserved
              raw_word (w:0) +              # andxoffset
              raw_word (w:fid) +            # fid
              raw_dword (d:offset) +        # offset
              raw_word (w:length) +         # Max count low
              raw_word (w:length) +         # Min count
              raw_dword (d:0xFFFFFFFF) +    # Reserved or max count high ?
              raw_word (w:length) +         # Remaining
              raw_dword (d:offset_high) ;   # high offset

 parameters = smb_parameters (data:parameters);

 data = pad + smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 return smb_sendrecv (data:packet);
}


##
# finds a file in a directory, including its subdirectories
#
# @param dir    - directory in which to find a file
#
# @return       - full path of the found file
#                 or NULL if not found
##
function find_a_file_in_dir(dir)
{
  local_var fh, file;

  file = NULL;

  fh = FindFirstFile(pattern:dir + "\*");
  while (! isnull(fh))
  {
    # file found
    if(!(fh[2] & FILE_ATTRIBUTE_DIRECTORY))
    {
      if (!(fh[2] & (FILE_ATTRIBUTE_REPARSE_POINT
                     | 0x40       # FILE_ATTRIBUTE_DEVICE
                     | 0x4000     # FILE_ATTRIBUTE_ENCRYPTED
                    )
            )
          )
      {
        file = dir + "\" + fh[1];
        break;
      }
    }
    # search in sub-directories
    else if (fh[1] != "." && fh[1] != "..")
    {
      file = find_a_file_in_dir(dir: dir + "\" + fh[1]);
      if (!isnull(file)) return file;
    }
    fh = FindNextFile(handle:fh);
  }

  return file;
}


###
# finds a file (any) in a share
#
# @param  share   - the share in which to find a file
# @return file name if found
#         or NULL if not found
###
function find_a_file(share)
{
  local_var ret, parameters;

  if(! smb_tree_connect_and_x(share:share))
  {
    debug_print("Failed to connect to network share '" + share + "'.");
    return NULL;
  }

  # starting at the top level of the share
  return find_a_file_in_dir(dir:NULL);
}


#
# Main
#

# get accessible shares
accessible_shares = get_kb_item_or_exit("SMB/accessible_shares/1");

# get a list of shares
shares = get_kb_list("SMB/shares");
if (isnull(shares)) exit(1, "The 'SMB/shares' KB items are missing.");


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
# find a file in one of the accessible shares
#
file = NULL;
foreach share (make_list(shares))
{
  if (share != "IPC$" && share >< accessible_shares)
  {
    file = find_a_file(share:share);
    if (! isnull(file)) break;
  }
}

if(isnull(file))
{
  close(soc);
  exit(1, "Could not find a file in accessible shares.");
}


# open the file
fh= CreateFile(file:file, desired_access:FILE_GENERIC_READ,file_attributes:0,
                 share_mode:FILE_SHARE_READ,create_disposition:OPEN_EXISTING);
if(isnull(fh))
{
  close(soc);
  exit(1, "Failed to open "+file+ ".");
}
fid = fh[0];

# read at a very large offset
ret = my_smb_read_and_x(fid:fid, offset:0xffffffff, offset_high: 0x7fffffff, length:10);

# close the file
CloseFile(handle:fh);

close(soc);

if (isnull(ret)) exit(1, "No response from the server to a SMB ReadAndX request.");


# get status code
code = get_header_nt_error_code(header:ret);
if (code == STATUS_INVALID_PARAMETER)
{
  security_hole(port:port);
}
else if( code == 0x00010002)
{
  audit(AUDIT_HOST_NOT, "affected");
}
else
{
  exit(1, "Unexpected status code (" + code + ").");
}
