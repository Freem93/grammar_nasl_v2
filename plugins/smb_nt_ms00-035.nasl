#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11330);
  script_version("$Revision: 1.39 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

  script_cve_id("CVE-2000-0402");
  script_bugtraq_id(1281);
  script_osvdb_id(557);
  script_xref(name:"MSFT", value:"MS00-035");
  script_xref(name:"MSKB", value:"263968");

  script_name(english:"MS00-035: MS SQL7.0 Service Pack may leave passwords on system (263968)");
  script_summary(english:"Reads %temp%\sqlsp.log");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is vulnerable to an information disclosure
attack.");
  script_set_attribute(attribute:"description", value:
"The installation process of the remote MS SQL server left a file named
'sqlsp.log' on the remote host. This file contains the password
assigned to the 'sa' account of the remote database.

An attacker may use this flaw to gain administrative access to the
database server.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms00-035");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patches from MS00-035 or upgrade MS SQL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft SQL Server Payload Execution via SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS00-035';
kb = "263968";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/WindowsVersion');


common = hotfix_get_systemroot();
if (!common) exit(1, "Can't get system root.");

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"TEMP");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) )
{
 NetUseDel();
 exit(1);
}

value[1] = ereg_replace(pattern:"%systemroot%", string:value[1], replace:common, icase:TRUE);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
rootfile =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\sqlsp.log", string:value[1]);


r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

handle =  CreateFile (file:rootfile, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
  CloseFile(handle:handle);
  NetUseDel();

  if (
    defined_func("report_xml_tag") &&
    !isnull(bulletin) &&
    !isnull(kb)
  ) report_xml_tag(tag:bulletin, value:kb);

  hotfix_security_warning();
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);

  exit(0);
}

NetUseDel();
exit(0, "The host is not affected.");


