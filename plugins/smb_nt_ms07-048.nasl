#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25901);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-3032", "CVE-2007-3033", "CVE-2007-3891");
 script_bugtraq_id(25287, 25304, 25306);
 script_osvdb_id(36391, 36392, 36393);
 script_xref(name:"MSFT", value:"MS07-048");
 script_xref(name:"CERT", value:"121024");
 script_xref(name:"CERT", value:"558648");
 script_xref(name:"CERT", value:"542808");

 script_name(english:"MS07-048: Vulnerabilities in Windows Gadgets Could Allow Remote Code Execution (938123)");
 script_summary(english:"Determines the presence of update 938123");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Desktop
Gadgets.");
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows is missing a critical security
update that fixes several vulnerabilities in the Desktop Gadgets.

An attacker may exploit these flaws to execute arbitrary code on the
remote host. To exploit this flaw, an attacker would need to lure the
user into adding a malicious RSS feed or mail contact or using a
malicious weather link.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-048");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-048';
kbs = make_list("938123");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);


login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


path = hotfix_get_programfilesdir();
if (!path) exit (1, "Failed to get the Program Files directory.");


dir =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Windows Sidebar\Gadgets\RSSFeeds.Gadget", string:path);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

retx  = FindFirstFile(pattern:dir + "\??-??");
if (isnull(retx) || strlen(retx[1]) != 5)
{
 NetUseDel();
 exit(0);
}

xml = dir + "\" + retx[1] + "\gadget.xml";

handle =  CreateFile (file:xml, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 data = ReadFile(handle:handle, offset:0, length:4096);
 CloseFile(handle:handle);

 if (egrep(pattern:'<version><!--_locComment_text="{Locked}"-->[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+</version>', string:data))
 {
  version = ereg_replace(pattern:'.*<version><!--_locComment_text="{Locked}"-->([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)</version>.*', string:data, replace:"\1");
  v = split(version, sep:".", keep:FALSE);

  if ( !isnull(v) )
    if ( int(v[0]) == 1 &&  int(v[1]) < 1 ) {
 set_kb_item(name:"SMB/Missing/MS07-048", value:TRUE);
 info =
   '\n  Path : ' + share-'$' + xml +
   '\n  Detected version : ' + version +
   '\n  Fixed version : 1.1.0.0\n';

 hotfix_add_report(info, bulletin:bulletin, kb:'938123');
 hotfix_security_warning();
 }
 }
}

NetUseDel();
