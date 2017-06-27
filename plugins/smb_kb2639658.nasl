#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@

include("compat.inc");


if (description)
{
  script_id(56711);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2012/06/17 00:27:30 $");

  script_cve_id("CVE-2011-3402");
  script_bugtraq_id(50462);
  script_osvdb_id(76843);
  script_xref(name:"CERT", value:"316553");

  script_name(english:"MS KB2639658: Vulnerability in TrueType Font Parsing Could Allow Elevation of Privilege (DEPRECATED)");
  script_summary(english:"Checks permissions on t2embed.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a code execution vulnerability in its
font parsing engine."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an unspecified code execution vulnerability in
the Win32k TrueType font parsing engine.  Specially crafted TrueType
fonts are not properly handled, which could allow arbitrary code
execution in kernel mode.  A remote attacker could exploit this
vulnerability by tricking a user into viewing a specially crafted
TrueType font (e.g., via web or email). 

This vulnerability is reportedly exploited by the Duqu malware and is
being exploited in the wild.

Note that this plugin has been deprecated on December 13, 2011 with
the publication by Microsoft of MS11-087."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.crysys.hu/");
  script_set_attribute(attribute:"see_also",value:"http://www.symantec.com/connect/w32_duqu_precursor_next_stuxnet");
  # http://www.symantec.com/connect/w32-duqu_status-updates_installer-zero-day-exploit
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?70696c53");
  script_set_attribute(attribute:"see_also",value:"http://technet.microsoft.com/en-us/security/advisory/2639658");
  script_set_attribute(attribute:"see_also",value:"http://support.microsoft.com/kb/2639658");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the workaround referenced in Microsoft Security Advisory
(2639658).  This workaround may cause some fonts to display
improperly.  Refer to the advisory for more information."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

# This script has been disabled and is intended to be blank.
# Disabled on 2011/12/23. Deprecated by smb_nt_ms11-087.nasl.
exit(0, "Deprecated - replaced by smb_nt_ms11-087.nasl");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

ACCESS_DENIED_ACE_TYPE = 1; # this should probably be put into an include file

##
# Opens the given file.  Assumes an absolute path will be given and
# the caller has already connected to the appropriate share.
#
# @anonparam path pathname of the file to open
#
# @return file handle for 'path' if it exists could be opened,
#         NULL otherwise
##
function open_file()
{
  local_var path, fh;
  path = substr(_FCT_ANON_ARGS[0], 2); # strip leading drive information

  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  return fh;
}

##
# Gets the DACL of the given file
#
# @anonparam fh handle of the file to obtain the DACL for
#
# @return DACL associated with 'fh'
##
function get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
  if (isnull(sd))
  {
    debug_print("Unable to access security descriptor.");
    return NULL;
  }
  
  dacl = sd[3];
  if (isnull(dacl))
  {
    debug_print("Unable to retrieve DACL.");
    return NULL;
  }
  
  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
  {
    debug_print("Error parsing DACL.");
    return NULL;
  }

  return dacl;
}

##
# Checks the permissions of the given file to see if the workaround
# from MS KB2639658 is being used
#
# @anonparam path pathname of the file to check
#
# @return TRUE if the file exists and the workaround is not in place,
#         FALSE otherwise
##
function workaround_missing()
{
  local_var path, fh, dacl, ace, sid, rights, type;
  path = _FCT_ANON_ARGS[0];

  fh = open_file(path);
  if (isnull(fh))
  {
    debug_print('Unable to open ' + path);
    return FALSE;
  }

  dacl = get_dacl(fh);
  CloseFile(handle:fh);
  if (isnull(dacl))
  {
    debug_print('Unable to get DACL for ' + path);
    return FALSE;
  }

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace))
    {
      debug_print("Error parsing ACE.");
      continue;
    }
  
    rights = ace[0];
    type = ace[3];
    sid = sid2string(sid:ace[1]);
    if (isnull(sid))
    {
      debug_print(1, "Error parsing SID.");
      continue;
    }
  
    # Explicitly check for the workaround:
    # a 1) an deny ACE 2) for Everyone 3) for full access
    if (
      type == ACCESS_DENIED_ACE_TYPE &&
      sid == '1-1-0' &&
      rights & FILE_ALL_ACCESS == FILE_ALL_ACCESS
    )
    {
      return FALSE; # workaround exists, therefore workaround_missing is FALSE
    }
  }
 
  return TRUE; # if the ACE created by the workaround wasn't seen, the workaround is missing
}
  
get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) exit(0, 'Host is not affected based on its version / service pack.');
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");

arch = get_kb_item_or_exit('SMB/ARCH');
root = hotfix_get_systemroot();
paths = NULL;

if (hotfix_check_sp(xp:4, win2003:3) > 0)
{
  # For 32-bit systems, enter the following command at an administrative command prompt:
  # Echo y| cacls "%windir%\system32\t2embed.dll" /E /P everyone:N
  if (arch == 'x86')
    paths = make_list(root + "\system32\t2embed.dll");

  # For 64-bit systems, enter the following command from an administrative command prompt:
  # Echo y| cacls "%windir%\system32\t2embed.dll" /E /P everyone:N
  # Echo y| cacls "%windir%\syswow64\t2embed.dll" /E /P everyone:N
  if (arch == 'x64')
    paths = make_list(root + "\system32\t2embed.dll", root + "\syswow64\t2embed.dll");
}
else if (hotfix_check_sp(vista:3, win7:2) > 0)
{
  # For 32-bit systems, enter the following command at an administrative command prompt:
  # Takeown.exe /f "%windir%\system32\t2embed.dll"
  # Icacls.exe "%windir%\system32\t2embed.dll" /deny everyone:(F)
  if (arch == 'x86')
    paths = make_list(root + "\system32\t2embed.dll");

  # For 64-bit systems, enter the following command at an administrative command prompt:
  # Takeown.exe /f "%windir%\system32\t2embed.dll"
  # Icacls.exe "%windir%\system32\t2embed.dll" /deny everyone:(F)
  # Takeown.exe /f "%windir%\syswow64\t2embed.dll"
  # Icacls.exe "%windir%\syswow64\t2embed.dll" /deny everyone:(F)
  if (arch == 'x64')
    paths = make_list(root + "\system32\t2embed.dll", root + "\syswow64\t2embed.dll");
}

if (isnull(paths))
  exit(0, 'The version of Windows installed on this host doesn\'t appear to be affected.');

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:root);
name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if (!get_port_state(port))exit(1, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc)exit(1, "Failed to open a socket on port "+port+".");

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  exit(1, "Unable to access the '" + share + "' share.");
}

vuln_paths = make_list();

foreach path (paths)
{
  if (workaround_missing(path))
    vuln_paths = make_list(vuln_paths, path);
} 

NetUseDel();

if (max_index(vuln_paths) == 0)
{
  exit(0, 'The host is not affected.');
}
else
{
  if (max_index(vuln_paths) == 1) s = ' has';
  else s = 's have';

  report = '\nThe following file' + s + ' not been modified by the workaround :\n\n' + join(vuln_paths, sep:'\n') + '\n';
  security_hole(port:port, extra:report);
}
