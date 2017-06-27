#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11989);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2003-0904");
 script_bugtraq_id(9118, 9409);
 script_osvdb_id(3490);
 script_xref(name:"MSFT", value:"MS04-002");

 script_name(english:"MS04-002: Exchange Privilege Escalation (832759)");
 script_summary(english:"Checks for MS Hotfix Q832759");

 script_set_attribute(attribute:"synopsis", value:"It is possible to access other users mailboxes.");
 script_set_attribute(attribute:"description", value:
"The remote host is running an unpatched version of Microsoft Exchange
that could allow an attacker with a valid Exchange account to access
another user's mailbox using Outlook for Web Access");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-002");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-002';
kb = '832759';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);


if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 65)) exit(0, "Exchanged is not affected based on its version.");

sp = get_kb_item ("SMB/Exchange/SP");
if ( sp && (sp >= 1)) exit (0, "Exchange is not affected based on its SP.");

if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");


if (is_accessible_share())
{
 path = get_kb_item ("SMB/Exchange/Path") + "\bin";
 if ( hotfix_is_vulnerable(os:"5.2", file:"exprox.dll", version:"6.5.6980.57", dir:path, bulletin:bulletin, kb:kb) )
 {
 set_kb_item(name:"SMB/Missing/MS04-002", value:TRUE);
 hotfix_security_note();
 hotfix_check_fversion_end();
 exit(0);
 }
 hotfix_check_fversion_end();
 exit(0, "The host is not affected.");
}
else exit(1, "is_accessible_share() failed.");
