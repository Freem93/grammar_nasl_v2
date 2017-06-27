#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25691);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
  "CVE-2006-7192",
  "CVE-2007-0041",
  "CVE-2007-0042",
  "CVE-2007-0043"
 );
 script_bugtraq_id(20753, 24778, 24791, 24811);
 script_osvdb_id(35269, 35954, 35955, 35956);
 script_xref(name:"IAVA", value:"2007-A-0037");
 script_xref(name:"MSFT", value:"MS07-040");
 script_xref(name:"EDB-ID", value:"30281");

 script_name(english:"MS07-040: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (931212)");
 script_summary(english:"Determines the version of the ASP.Net DLLs");

 script_set_attribute(attribute:"synopsis", value:"The remote .Net Framework is vulnerable to code execution attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ASP.NET framework that
contains multiple vulnerabilities :

  - A PE Loader vulnerability could allow an attacker to
    execute arbitrary code with the privileges of the
    logged-on user.

  - An ASP.NET NULL byte termination vulnerability could
    allow an attacker to retrieve the content of the web
    server.

  - A JIT compiler vulnerability could allow an attacker to
    execute arbitrary code with the privileges of the
    logged-on user.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-040");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.0, 1.1
and 2.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119, 200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS07-040';
kbs = make_list("928365", "928367", "929729");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll10 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.1.4322\System.web.dll", string:rootfile);
dll11 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.0.3705\System.web.dll", string:rootfile);
dll20 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\System.web.dll", string:rootfile);

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}


handle =  CreateFile (file:dll20, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
dll = dll20;

if ( isnull(handle) )
{
 handle = CreateFile (file:dll11, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 dll = dll11;

 if ( isnull(handle) )
 {
   handle = CreateFile (file:dll10, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
   dll = dll10;
 }
}



if( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  # 1.0 SP 3
  if (
    (v[0] == 1 && v[1] == 0 && v[2] < 3705) ||
    (v[0] == 1 && v[1] == 0 && v[2] == 3705 && v[3] < 6060)
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 1.0.3705.606\n',
                      bulletin:bulletin,
                      kb:'928367');
    set_kb_item(name:"SMB/Missing/MS07-040", value:TRUE);
    hotfix_security_hole();
  }
  else if (
       (v[0] == 1 && v[1] == 1 && v[2] < 4322) ||
       (v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2407)
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 1.1.4322.2407\n',
                      bulletin:bulletin,
                      kb:'929729');
    set_kb_item(name:"SMB/Missing/MS07-040", value:TRUE);
    hotfix_security_hole();
  }
  # 2.0
  else if(
       (v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
       (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 832)
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 2.0.50727.832\n',
                      bulletin:bulletin,
                      kb:'928365');
    set_kb_item(name:"SMB/Missing/MS07-040", value:TRUE);
    hotfix_security_hole();
  }
 }
}

NetUseDel();
