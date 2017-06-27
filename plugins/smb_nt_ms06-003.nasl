#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20390);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2006-0002");
 script_bugtraq_id(16197);
 script_osvdb_id(22305);
 script_xref(name:"CERT", value:"252146");
 script_xref(name:"MSFT", value:"MS06-003");

 script_name(english:"MS06-003: Vulnerability in TNEF Decoding in Microsoft Outlook and Microsoft Exchange Could Allow Remote Code Execution (902412)");
 script_summary(english:"Determines the version of OutLook / Exchange");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client or server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Outlook or Exchange containing
a bug in the Transport Neutral Encapsulation Format (TNEF) MIME
attachment handling routine that could allow an attacker execute
arbitrary code on the remote host by sending a specially crafted
email.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-003");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000, 2002, XP,
2003, Exchange 5.0, 5.5 and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/01/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-003';
kbs = make_list("892841", "892842", "892843", "894689", "902412");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


kb = '902412';

versions = hotfix_check_outlook_version();
vuln = 0;
if (versions)
{
  foreach item (keys(versions))
  {
    version = item - 'SMB/Office/Outlook/' - '/Path';
    path = versions[item];

    if (version == "9.0")
    {
      kb = '892842';
      if ( hotfix_check_fversion(path:path, file:"Outex.dll", version:"8.30.3197.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) vuln++;
    }
    else if (version == "10.0")
    {
      kb = '892841';
      if ( hotfix_check_fversion(path:path, file:"Outllibr.dll", version:"10.0.6711.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) vuln++;
    }
    else if (version == "11.0")
    {
      kb = '892843';
      if ( hotfix_check_fversion(path:path, file:"Outllib.dll", version:"11.0.8002.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) vuln++;
    }
  }
}

version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

if (version == 50)
{
 kb = '894689';
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.0.1462.22", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
   vuln++;
 }
}
else if (version == 55)
{
 kb = '894689';
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 4) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.5.2658.34", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
   vuln++;
 }
}
else if (version == 60)
{
 kb = '894689';
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.0.6617.47", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
   vuln++;
 }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
