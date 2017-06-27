#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34401);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-4020");
 script_bugtraq_id(31693);
 script_osvdb_id(49052);
 script_xref(name:"MSFT", value:"MS08-056");

 script_name(english:"MS08-056: Microsoft Office CDO Protocol (cdo:) Content-Disposition: Attachment Header XSS (957699)");
 script_summary(english:"Determines if a given registry entry is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote installation of Microsoft Office is vulnerable to an
information disclosure flaw.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that is
subject to an information disclosure flaw.

When a user clicks on a special CDO URL, an attacker could inject a
client side script that could be used to disclose information.

To succeed, the attacker would have to send a rogue CDO URL to a user
of the remote computer and have it click it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-056");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-056';
kbs = make_list("956464");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);


office_versions = hotfix_check_office_version ();
if ( !office_versions || !office_versions["10.0"] ) exit(0, "Office version 10.0 not found.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");


r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Classes\PROTOCOLS\Handler\cdo";
item = "CLSID";
value = NULL;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:item);
  RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();

if ( ! isnull(value) ) {
 set_kb_item(name:"SMB/Missing/MS08-056", value:TRUE);

 kb       = '956464';
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_note();
 }
