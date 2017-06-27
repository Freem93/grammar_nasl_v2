#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12208);
 script_version("$Revision: 1.41 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0380");
 script_bugtraq_id(9105, 9107, 9658);
 script_osvdb_id(3143, 3144, 3307, 5242);
 script_xref(name:"CERT", value:"323070");
 script_xref(name:"MSFT", value:"MS04-013");

 script_name(english:"MS04-013: Cumulative Update for Outlook Express (837009)");
 script_summary(english:"Checks for ms04-013");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host has a version of Outlook Express that has a bug in its
MHTML URL processor that could allow an attacker to execute arbitrary
code on this host.

To exploit this flaw, an attacker would need to send a malformed email
to a user of this host using Outlook, or would need to lure him into
visiting a rogue website.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-013");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/04/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms04-018.nasl", "smb_nt_ms05-030.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("SMB/OutlookExpress/MSOE.dll/Version", "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-013';
kb = '837009';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
if(!port) port = 139;


if ( hotfix_check_sp(win2k:5,xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"823353") <= 0 ) exit(0);
if ( get_kb_item("SMB/897715") ) exit(0);

patch = get_kb_item ("SMB/KB823353");
if ( patch == TRUE ) exit (0);


version = get_kb_item("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) ||
	      (v[0] == 5 && v[1] == 50 && v[2] < 4922) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4922 && v[3] < 1500 ) ) { {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }}
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2720) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2720 && v[3] < 3000 ) ) { {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }}

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2720 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1409 ) ) { {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }}

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 137 ) ) { {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }}
	}
