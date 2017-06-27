#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55791);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-1263");
  script_bugtraq_id(49040);
  script_osvdb_id(74406);
  script_xref(name:"MSFT", value:"MS11-061");
  script_xref(name:"IAVB", value:"2011-B-0103");

  script_name(english:"MS11-061: Vulnerability in Remote Desktop Web Access Could Allow Elevation of Privilege (2546250)");
  script_summary(english:"Checks for the patch");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote Windows host has a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Remote Desktop Web Access running on the remote host
has a reflected cross-site scripting vulnerability. Input to the
'ReturnUrl' parameter of login.aspx is not properly sanitized.

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in arbitrary script
code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-061");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-061';
kb = "2546250";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (!get_kb_item('WMI/server_feature/134'))
  exit(0, 'The Remote Desktop Web Access role is not enabled, therefore the host is not affected.');

root = hotfix_get_systemroot();
match = eregmatch(string:root, pattern:'^([A-Za-z]):(.+)$');
if (isnull(match)) exit(1, 'Unable to parse path \'' + root + '\'.');

share = match[1] + '$';
rdweb = match[2] + "\Web\RDWeb\Pages\";

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# find which directory (or directories) login.aspx is located in, and read their contents
files = make_array();
dir = FindFirstFile(pattern:rdweb + '*');

while (!isnull(dir[1]))
{
  if (dir[2] & FILE_ATTRIBUTE_DIRECTORY && dir[1] != '.' && dir[1] != '..')
  {
    file = rdweb + dir[1] + "\login.aspx";
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (fh)
    {
      i = 0;
      data = NULL;
      length = GetFileSize(handle:fh);
      if (length > 100000) length = 100000;  # the file is ~50k and the line of interest is near the top

      while (i < length)
      {
        tmp = ReadFile(handle:fh, offset:i, length:30000);  # iirc length is a 16 bit field
        if (strlen(tmp) == 0)
        {
          debug_print('Error reading ' + file);
          break;
        }
        # either the file is unicode or i've somehow specified unicode during the transfer
        data += str_replace(string:tmp, find:'\x00', replace:'');
        i += strlen(tmp);
      }

      CloseFile(handle:fh);

      file = share - '$' + ':' + file;
      files[file] = data;
    }
  }

  dir = FindNextFile(handle:dir);
}

NetUseDel();

if (max_index(keys(files)) == 0)
  exit(1, 'No files named login.aspx were found under \'' + rdweb + '\'.');

unpatched = make_list();

foreach file (keys(files))
{
  # this string indicates it's patched
  if ('HttpUtility.UrlEncode(strReturnUrlPage)' >!< files[file])
    unpatched = make_list(unpatched, file);
}

if (max_index(unpatched) == 0) audit(AUDIT_HOST_NOT, 'affected');

if (max_index(unpatched) == 1)
  s = ' is';
else
  s = 's are';

report = '\nThe following file' + s + ' not patched :\n\n';

foreach file (unpatched)
  report += file + '\n';

hotfix_add_report(report, bulletin:bulletin, kb:kb);
hotfix_security_warning();

set_kb_item(name:"www/0/XSS", value:TRUE);
set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
