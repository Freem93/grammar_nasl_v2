#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11306);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0369");
 script_bugtraq_id(4958);
 script_osvdb_id(5314);
 script_xref(name:"MSFT", value:"MS02-026");
 script_xref(name:"MSKB", value:"322289");

 script_name(english:"MS02-026: ASP.NET Worker Process StateServer Mode Remote Overflow (322289)");
 script_summary(english:"Checks for MS Hotfix Q322289");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote ASP.NET installation might be vulnerable to a buffer
overflow when an application enables StateServer mode.

An attacker could use it to cause a denial of service or run arbitrary
code with the same privileges as the process being exploited
(typically an unprivileged account).");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-026");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ASP.NET.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/06/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_W2K.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS02-026';
kb = '322289';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

version = get_kb_item("SMB/WindowsVersion");
if(ereg(pattern:"^(1[0-9]|[6-9]\.[0-9])|(5\.[2-9])", string:version)) audit(AUDIT_HOST_NOT,"affected");


login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
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


key = "SOFTWARE\Microsoft\.NetFramework";
item  = "InstallRoot";


key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\S321884";
  item = "Description";

  key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h2) )
  {
   value = RegQueryValue(handle:key_h2, item:item);
   if (isnull (value) || !ereg(pattern:"Service Pack [2-9]", string:value[1]))
   {
    key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\NDP10SP317396\M322289";

    key_h3 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( isnull(key_h3) )
 {
 set_kb_item(name:"SMB/Missing/MS02-026", value:TRUE);
 report = '\nThe following registry key is missing :\n'+
          'is missing :\n\n'+
          '  HKEY_LOCAL_MACHINE\\'+key+'\n\n'+
          'which indicates the relevant patch has not been applied.\n';
 hotfix_add_report(report, bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }
    else
      RegCloseKey (handle:key_h3);
   }

   RegCloseKey(handle:key_h2);
  }

 }

 RegCloseKey (handle:key_h);
}


RegCloseKey (handle:hklm);
NetUseDel ();


