#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2011/02/08.  Use smb_nt_ms11-006.nasl (plugin ID 51906) instead.


include('compat.inc');

if (description)
{
  script_id(51424);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id("CVE-2010-3970");
  script_bugtraq_id(45662);
  script_osvdb_id(70263);
  script_xref(name:"IAVA", value:"2011-A-0019");

  script_name(english:"MS KB2490606: Vulnerability in Graphics Rendering Engine Could Allow Remote Code Execution");
  script_summary(english:"Checks the ACL for shimgvw.dll");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote host using
the graphics rendering engine.");

  script_set_attribute(attribute:"description", value:
"If a remote attacker can trick a user on the affected host into
opening a specially crafted bitmap file, the attacker could leverage
an as-yet unpatched vulnerability in the graphics rendering engine
that arises due to its failure to validate the 'biClrUsed' parameter
and  thereby execute arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2490606");
  script_set_attribute(attribute:"solution", value:
"Consider applying the workaround provided by Microsoft.

Note, though, that applying the workaround will lead to some media
files not being displayed correctly.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/01/06");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

# Deprecated
exit(0, "This plugin has been deprecated. Use smb_nt_ms11-006.nasl (plugin ID 51906) instead.");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");


# Local version of smb_check_success so that we can check
# the return code for Access Denied
function local_smb_check_success(data)
{
  local_var header, flags2, code;

  # Some checks in the header first
  header = get_smb_header (smbblob:data);
  if (!header)
    return FALSE;

  flags2 = get_header_flags2(header:header);
  if (flags2 && SMB_FLAGS2_32BIT_STATUS)
  {
    code = get_header_nt_error_code (header:header);
    if (code == STATUS_ACCESS_DENIED)
      return code;
    else if (code != STATUS_SUCCESS)
      return FALSE;
  }
  else
  {
    code = get_header_dos_error_code (header:header);
    if (code == ERROR_ACCESS_DENIED)
      return code;
    else if (code != NO_ERROR)
      return FALSE;
  }
  return TRUE;
}

# Local version of smb_create_and_x function so that we can check
# the return code for Access Denied
function local_smb_create_and_x (name, desired_access, flags_attributes, share_mode, create_disposition, create_options)
{
  local_var header, parameters, data, packet, ret, offset, fid, pad, filename, status;

  if (session_is_smb2())
  {
    return smb2_create(
                name:name,
                desired_access:desired_access,
                flags_attributes:flags_attributes,
                share_mode:share_mode,
                create_disposition:create_disposition,
                create_options:create_options
                );
  }

  header = smb_header (Command:SMB_COM_NT_CREATE_ANDX,
                       Status:nt_status(Status:STATUS_SUCCESS));

  pad = NULL;
  if (session_is_unicode() == 1) pad = raw_byte(b:0);

  filename = cstring(string:name);

  parameters = raw_byte (b:255) + # no further command
               raw_byte (b:0) +
               raw_word (w:0) +
               raw_byte (b:0) +
               raw_word (w:strlen(cstring(string:name,_null:1))) +
               raw_dword(d:0x16)           +  # flags to change
               raw_dword(d:0)              +  # root fid
               raw_dword(d:desired_access) +  # access_mask
               raw_dword(d:0) + raw_dword(d:0) +  # allocation size
               raw_dword (d:flags_attributes) + # file attributes
               raw_dword (d:share_mode)    +  # share access
               raw_dword (d:create_disposition) + # Disposition
               raw_dword (d:create_options) + # create options
               raw_dword (d:2)              + # impersonation
               raw_byte (b:3);                # security flags

  parameters = smb_parameters (data:parameters);
      
  data = pad + filename;

  data = smb_data (data:data);

  packet = netbios_packet(header:header, parameters:parameters, data:data);

  ret = smb_sendrecv(data:packet);
  if (!ret) return NULL;

  # Check the return code.  If we get access denied, return -1
  # For any other error code return NULL
  # Otherwise return the file handle
  status = local_smb_check_success (data:ret);
  if (status == STATUS_ACCESS_DENIED || status == ERROR_ACCESS_DENIED)
  {
    return make_list(-1);
  }
  else if (status == FALSE)
  {
    return NULL;
  }

  parameters = get_smb_parameters(smbblob:ret);
  if (!parameters || (strlen(parameters) < 63))
    return NULL;

  offset = get_word (blob:parameters, pos:2);

  ret = NULL;
  ret[0] = get_word(blob:parameters, pos:5); #FID
  ret[1] = substr(parameters, 55, 62); # SIZE

  return ret;
}

get_kb_item_or_exit('SMB/WindowsVersion');
arch = get_kb_item_or_exit('SMB/ARCH');

if (hotfix_check_sp(xp:4, win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

name     = kb_smb_name();
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();
port     = kb_smb_transport();

if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

session_init(socket:soc, hostname:name);

report = NULL;
winver = get_kb_item_or_exit("SMB/WindowsVersion");
if (winver == '5.1' || winver == '5.2')
{
  winroot = hotfix_get_systemroot();
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:winroot);
  path = ereg_replace(string:winroot, pattern:'^[A-Za-z]:(.*)', replace:"\1\system32\");
  dll = path+'shimgvw.dll';
  

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }
  
  vuln32 = TRUE;
  vuln64 = FALSE;
  fh = local_smb_create_and_x(
    name:dll,
    desired_access:GENERIC_READ,
    flags_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING,
    create_options:0
  );
  
  if (isnull(fh))
  {
    NetUseDel();
    exit(1, "Unable to open file "+dll+".");
  }
  
  # If fh is -1, that means we got an access denied
  else if (fh[0] == -1) vuln32 = FALSE;
  
  # If we were able to access the file, that's enough to say the 
  # workaround hasn't been implemented.
  else CloseFile(handle:fh);

  # If this is a 64-bit system, we also have to look in the syswow64 directory
  if (arch == 'x64')
  {
    vuln64 = TRUE;
    path64 = ereg_replace(string:winroot, pattern:'^[A-Za-z]:(.*)', replace:"\1\syswow64\");
    dll64 = path64 + 'shimgvw.dll';
  
    fh = local_smb_create_and_x(
      name:dll64,
      desired_access:GENERIC_READ,
      flags_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING,
      create_options:0
    );
    
    if (isnull(fh))
    {
      NetUseDel();
      exit(1, "Unable to open file "+dll64+".");
    }

    # If fh is -1, that means we got an access denied
    else if (fh[0] == -1) vuln64 = FALSE;
  
    # If we were able to access the file. That's enough to say the workaround
    # hasn't been implemented
    else CloseFile(handle:fh);
  }

  # Clean up
  NetUseDel();
  
  if (vuln32 || vuln64)
  {
    report = 'The Everyone group has not been denied full rights to :\n\n';
    if (vuln32)
    {
      report += dll+'\n';
    }
    if (vuln64) 
    {
      report += dll64+'\n';
    }
  }
}

# In Windows Vista/2008 we try to read the IconsOnly registry key for the
# logged in user.
else if (winver == '6.0')
{
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to IPC$ share.");
  }

  # Connect to remote registry
  hku_handle = RegConnectRegistry(hkey:HKEY_USERS);
  if (isnull(hku_handle))
  {
    NetUseDel();
    exit(1, "Can't connect to remote registry.");
  }

  # Loop through each user and check if Explorer\IconsOnly is set to true
  userloggedin = FALSE;
  vuln = NULL; 
  username = NULL;
  info = RegQueryInfoKey(handle:hku_handle);
  for (i=0; i<info[1]; i++)
  {
    item = RegEnumKey(handle:hku_handle, index:i);
    if ('S-1-5-21-' >< item)
    {
      userloggedin = TRUE;
      if ('_Classes' >!< item)
      {
        # Try to determine the username of the logged in user
        key = item + "\Volatile Environment";
        key_h = RegOpenKey(handle:hku_handle, key:key, mode:MAXIMUM_ALLOWED);
        if (!isnull(key_h))
        {
          item2 = RegQueryValue(handle:key_h, item:"USERNAME");
          if (!isnull(item2)) username = item2[1];

          RegCloseKey(handle:key_h);
        }
        if (isnull(username)) username = "Unknown";

        # Now check for the workaround
        key = item + "\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
        key_h = RegOpenKey(handle:hku_handle, key:key, mode:MAXIMUM_ALLOWED);
        if (!isnull(key_h))
        {
          item2 = RegQueryValue(handle:key_h, item:"IconsOnly");
          if (isnull(item2))
          {
            RegCloseKey(handle:key_h);
            RegCloseKey(handle:hku_handle);
            NetUseDel();
            exit(1, "Couldn't read the "+key+"\IconsOnly registry key.");
          }
          if (item2[1] == 0) vuln = TRUE;
          else vuln = FALSE;

          RegCloseKey(handle:key_h);
        }
      }
    }
  }
  RegCloseKey(handle:hku_handle);
  NetUseDel();
  if (!userloggedin) exit(1, "Nessus could not check for the workaround because there are no users logged in to the console.");
  if (isnull(vuln)) exit(1, "Nessus could not determine if the workaround has been applied for the username "+username+".");
  if (vuln)
  {
    report =
      '\n  The workaround has not been applied for the following user : ' +
      '\n  User : ' + username + '\n' +
      '\n  Note that this workaround has to be applied for each user.\n';
  }
  exit(0, "The workaround has been applied for the username "+username+".");
}
# Update the reporting based on windows version
if (report)
{
  if (report_verbosity > 0)
  {
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The host is not affected.");
