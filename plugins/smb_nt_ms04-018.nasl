#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13643);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0215");
 script_bugtraq_id(10711);
 script_osvdb_id(7793);
 script_xref(name:"CERT", value:"869640");
 script_xref(name:"MSFT", value:"MS04-018");

 script_name(english:"MS04-018: Cumulative Security Update for Outlook Express (823353)");
 script_summary(english:"Checks for ms04-018 over the registry");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a cumulative security update for Outlook
Express that fixes a denial of service vulnerability in the Outlook
Express mail client.

To exploit this vulnerability, an attacker would need to send a
malformed message to a victim on the remote host.  The message will
crash the version of Outlook, thus preventing the user from reading
email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-018");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Outlook Express.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/07/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms05-030.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-018';
kb = '823353';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if ( get_kb_item("SMB/897715") ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);


version = get_kb_item ("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);
flag = 0;

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) ||
	      (v[0] == 5 && v[1] == 50 && v[2] < 4942) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4942 && v[3] < 400 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }flag ++; }
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2742) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2742 && v[3] < 2600 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }flag ++; }

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2742 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1437 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }flag ++; }

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 181 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-018", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }flag ++; }
	}

if ( flag == 0)
  set_kb_item (name:"SMB/KB823353", value:TRUE);
