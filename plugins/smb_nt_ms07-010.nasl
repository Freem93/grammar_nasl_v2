#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24334);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2006-5270");
 script_bugtraq_id(22479);
 script_osvdb_id(31888);
 script_xref(name:"MSFT", value:"MS07-010");
 script_xref(name:"CERT", value:"511577");

 script_name(english:"MS07-010: Vulnerability in Microsoft Malware Protection Engine Could Allow Remote Code Execution (932135)");
 script_summary(english:"Determines the version of Malware Protection Engine");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
AntiMalware program.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows Malware Protection
engine that is vulnerable to a bug in the PDF file handling routine
that could allow an attacker execute arbitrary code on the remote host
by sending a specially crafted file.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-010");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Defender and Live
OneCare.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:antigen");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_security");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_live_onecare");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS07-010';
kbs = make_list("932135");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

keys = make_list (
	"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
	"SOFTWARE\Microsoft\OneCare Protection\Signature Updates"
	);

foreach key (keys)
{
 value = NULL;
 item = "EngineVersion";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:item);
  RegCloseKey(handle:key_h);
 }

 if (!isnull(value))
 {
  v = split(value[1], sep:".", keep:FALSE);

  if ( ( (int(v[0]) == 1) && (int(v[1]) < 1) ) ||
       ( (int(v[0]) == 1) && (int(v[1]) == 1) && (int(v[2]) < 2101) ) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS07-010", value:TRUE);
 info =
   '\n  Installed version : ' + value[1] +
   '\n  Fixed version : 1.1.2101.0\n';
 hotfix_add_report(info, bulletin:"MS07-010", kb:"932135");
 hotfix_security_hole();
 }
   break;
  }
 }
}


RegCloseKey(handle:hklm);
NetUseDel();
