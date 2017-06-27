#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26019);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2007-2931");
 script_bugtraq_id(25461);
 script_osvdb_id(40126);
 script_xref(name:"MSFT", value:"MS07-054");
 script_xref(name:"CERT", value:"166521");
 script_xref(name:"EDB-ID", value:"30537");

 script_name(english:"MS07-054: Vulnerability in MSN Messenger and Windows Live Messenger Could Allow Remote Code Execution (942099)");
 script_summary(english:"Checks for MS07-054");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Messenger
service.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger or Windows Live Messenger.

The version of Messenger used on the remote host is vulnerable to a
remote buffer overflow in the way it handles webcam and video chat
sessions.  An attacker may exploit this vulnerability to execute
arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-054");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MSN Messenger 6.2, 7.0, 7.5
and 8.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms04-010.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');

 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-054';
kbs = make_list("942099");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
if ( ! version )
{
 version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/0F007175D9BDA3B40BD3531AB45B39F9/Version");
 if ( ! version ) exit(0);
}

a = ((version) & 0xFF000000) >> 24;
b = ((version & 0xFF0000)) >> 16;
c = version & 0xFFFF;

os = get_kb_item("SMB/WindowsVersion");


kb = '942099';
display_ver = strcat(a, '.', b, '.', c);

if ("5.0" >< os)
{
 if ( ( a < 7 ) ||
     ( (a == 7) && (b == 0) && (c < 820) ) )
 {
 info =
   '\n  Installed version : ' + display_ver +
   '\n  Fixed version : 7.0.820\n';
 hotfix_add_report(info, bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS07-054", value:TRUE);
 hotfix_security_hole();
 }
}
else
{
 if ( ( a < 8 ) ||
     ( (a == 8) && (b == 0) ) )
 {
 info =
   '\n  Installed version : ' + display_ver +
   '\n  Fixed version : 8.1.0178\n';
 hotfix_add_report(info, bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS07-054", value:TRUE);
 hotfix_security_hole();
 }
}
