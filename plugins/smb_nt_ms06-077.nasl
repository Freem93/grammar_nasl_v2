#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23839);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/04/23 21:04:51 $");

 script_cve_id("CVE-2006-5584");
 script_bugtraq_id(21495);
 script_osvdb_id(30817);
 script_xref(name:"CERT", value:"238064");
 script_xref(name:"MSFT", value:"MS06-077");

 script_name(english:"MS06-077: Vulnerability in Remote Installation Service Could Allow Remote Code Execution (926121)");
 script_summary(english:"Determines the parameters of the remote TFTP server");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through TFTPF.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of TFTPD installed by the Remote
Installation Service that allows everyone to overwrite files on the
remote host.

An attacker may exploit this flaw to replace SYSTEM files and execute
arbitrary code on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-077");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");

 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-077';
kb = '926121';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Determine where it's installed.
key = "SYSTEM\CurrentControlSet\Services\TFTPD";
item = "DisplayName";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (isnull(key_h))
{
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:item);

RegCloseKey(handle:key_h);

if (isnull(value))
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

fixed = 0;

key = "SYSTEM\CurrentControlSet\Services\TFTPD\Parameters";
item = "Masters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull(value))
   fixed = 1;

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();

if (fixed == 0)
 {
 set_kb_item(name:"SMB/Missing/MS06-077", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
