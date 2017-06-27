#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39795);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2009-1542");
  script_bugtraq_id(35601);
  script_osvdb_id(55837);
  script_xref(name:"MSFT", value:"MS09-033");

  script_name(english:"MS09-033: Vulnerability in Virtual PC and Virtual Server Could Allow Elevation of Privilege (969856)");
  script_summary(english:"Checks version of VMM.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Virtual PC or Virtual Server
that incorrectly validates privilege levels when executing specific
instructions in the Virtual Machine Monitor. An attacker who has
logged in to a guest operating system running under the affected
software can leverage this issue to run code with elevated privileges
inside the hosted guest operating system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Virtual PC 2004 and 2007
as well as Virtual Server 2005.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:virtual_pc");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:virtual_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-033';
kbs = make_list("969856");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/WindowsVersion");


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Determine if either product is installed.
Virtual_PC = FALSE;
Virtual_Server = FALSE;
hcf_init = TRUE;

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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

key = "SOFTWARE\Microsoft\Virtual PC";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  Virtual_PC = TRUE;
  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\Microsoft\Virtual Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  Virtual_Server = TRUE;
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (!Virtual_PC && !Virtual_Server) exit(0);


# Determine the product name.
prod_name = "";

path = hotfix_get_programfilesdir();
if (!path) exit(1, "Can't determine Program Files directory.");
share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);
if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

if (Virtual_PC) exe = path + "\\Microsoft Virtual PC\\Virtual PC.exe";
else exe = path + "\\Microsoft Virtual Server\\vssrvc.exe";

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

exe2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
fh = CreateFile(
  file               : exe2,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);

if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) prod_name = data['ProductName'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) prod_name = data['ProductName'];
      }
    }
  }
  CloseFile(handle:fh);
}
if (!prod_name) exit(0, "Can't determine the product name.");
NetUseDel(close:FALSE);


# Determine the fix based on the product name.
fix = "";

min = '0.0.0.0';
if ("Virtual PC 2007" >< prod_name)
{
  if (ereg(pattern:" SP1($|[^0-9])", string:prod_name))
  {
    fix = "1.1.656.0";
    min = '1.1.627.0';
  }
  else if (!ereg(pattern:" SP[0-9]", string:prod_name))
  {
    fix = "1.1.598.0";
    min = '1.1.563.0';
  }
}
if ("Virtual Server 2005" >< prod_name)
{
  if ('R2' >< prod_name)
  {
    min = '1.1.603.0';
  }
  else min = '1.1.465.1';
  fix = "1.1.656.0";
}
if ("Virtual PC 2004" >< prod_name)
{
  fix = "1.1.465.15";
  min = '1.1.465.1';
}
if (!fix) exit(0, "The installation is not vulnerable.");


# Finally, check the version of the affected file.
if (!is_accessible_share()) exit(1, "Can't access default share.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Can't get system root.");


kb = '969856';
if (hotfix_check_fversion(file:"VMM.sys", path:rootfile+"\System32\Drivers", version:fix, min_version:min, bulletin:bulletin, kb:kb) == HCF_OLDER)
{
  set_kb_item(name:"SMB/Missing/MS09-033", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
