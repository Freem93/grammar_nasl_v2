#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18025);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2005-0562");
 script_bugtraq_id(13114);
 script_osvdb_id(15468);
 script_xref(name:"MSFT", value:"MS05-022");
 script_xref(name:"CERT", value:"633446");

 script_name(english:"MS05-022: Vulnerability in MSN Messenger Could Lead to Remote Code Execution (896597)");
 script_summary(english:"Checks for MS05-022");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Messenger
service.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger.

The version of MSN Messenger used on the remote host is vulnerable to a
remote buffer overflow in the way it handles GIF files (with height and
width fields).

An attacker may exploit this vulnerability to execute arbitrary code on
the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-022");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for MSN Messenger 6.2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:msn_messenger");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms04-010.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version", "Host/patch_management_checks");

 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-022';
kb = '896597';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

version =  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version");
if ( ! version ) exit(0);

a = ((version) & 0xFF000000) >> 24;
b = ((version & 0xFF0000)) >> 16;
c = version & 0xFFFF;


if ( ( a == 6 ) &&
     ( (b < 2) || ( (b == 2) && (c < 208) ) ) )
 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
