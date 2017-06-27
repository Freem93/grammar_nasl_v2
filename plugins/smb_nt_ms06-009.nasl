#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20909);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-0008");
 script_bugtraq_id(16643);
 script_osvdb_id(23136);
 script_xref(name:"MSFT", value:"MS06-009");

 script_name(english:"MS06-009: Vulnerability in Korean Input Method Could Allow Elevation of Privilege (901190)");
 script_summary(english:"Determines the presence of update 901190");

 script_set_attribute(attribute:"synopsis", value:"A local user may elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Korean input
method that may allow a local attacker to execute arbitrary code on the
remote host.

To exploit this flaw, an attacker would need credentials to log into the
remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-009");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 and
Office 2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS06-009';
kbs = make_list("901190");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

#
# XP SP1, SP2, Windows Server 2003 SP0, SP1
#
if (hotfix_check_sp_range(xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

kb = '901190';

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Imekr61.ime", version:"6.1.3790.1", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Imekr61.ime", version:"6.2.2551.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1",       file:"Imekr61.ime", version:"6.1.2600.3", dir:"\system32", bulletin:bulletin, kb:kb)  )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
