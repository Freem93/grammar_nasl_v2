#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55131);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-1264");
  script_bugtraq_id(48175);
  script_osvdb_id(72937);
  script_xref(name:"MSFT", value:"MS11-051");
  script_xref(name:"IAVB", value:"2011-B-0068");

  script_name(english:"MS11-051: Vulnerability in Active Directory Certificate Services Web Enrollment Could Allow Elevation of Privilege (2518295)");
  script_summary(english:"Checks content of ASP pages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ASP application with a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"A reflected (or non-persistent) cross-site scriting vulnerability
exists in the version of Active Directory Certificate Services Web
Enrollment installed on the remote Windows host due to improper
validation of a request parameter.

By using a specially crafted link, an attacker could leverage the
vulnerability to gain elevated privileges and execute arbitrary
commands in the context of the target user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, 2008,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-051';
kb = "2518295";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);


winroot = hotfix_get_systemroot();
if (!winroot) exit(1, "Failed to get the system root.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Make sure Certificate Services is installed.
certsrv = FALSE;

key = "SOFTWARE\Classes\certocm.CertSrvSetup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) certsrv = TRUE;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


if (!certsrv)
{
  NetUseDel();
  exit(0, "Certificate Services is not installed.");
}
NetUseDel(close:FALSE);



# Check ASP source to see if the UserAgent request header is sanitized.
share = hotfix_path2share(path:winroot);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}
base =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\certsrv", string:winroot);


pages = make_list("Certrqxt.asp");
vuln_pat = '^[\t ]*' + "[^<'].+" + '=[\t ]*"UserAgent:[\t ]*<%=[\t ]*Request\\.ServerVariables[\t ]*\\([\t ]*"HTTP_USER_AGENT"[\t ]*\\)[\t ]*%>';


info = "";
foreach page (sort(pages))
{
  fh = FindFile(
    file:base+"\*\"+page,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    ofs = 0;
    chunk = 65535;
    vuln = FALSE;

    while (fsize > 0 && ofs <= fsize && !vuln)
    {
      data = ReadFile(handle:fh, length:chunk, offset:ofs);
      if (strlen(data) == 0) break;

      foreach line (split(data, keep:FALSE))
      {
        if (ereg(pattern:vuln_pat, string:line))
        {
          info += '  - File          : ' + (share-'$')+base + '\\*\\' + page + '\n' +
                  '    Affected line : ' + line + '\n\n';
          vuln = TRUE;
          break;
        }
      }

      # nb: re-read a little bit to make sure we didn't start reading
      #     in the middle of the line.
      ofs += chunk - 512;
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();


if (info)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);

  hotfix_add_report(chomp(info), bulletin:bulletin, kb:kb);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
