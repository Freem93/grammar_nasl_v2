#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31047);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-0103");
 script_bugtraq_id(27738);
 script_osvdb_id(41462);
 script_xref(name:"MSFT", value:"MS08-013");

 script_name(english:"MS08-013: Vulnerability in Microsoft Office Could Allow Remote Code Execution (947108)");
 script_summary(english:"Determines the version of Office");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that is
vulnerable to a buffer overflow when handling malformed documents.

An attacker may exploit this flaw to execute arbitrary code on this
host, by sending a malformed file to a user of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-013");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

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
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-013';
kbs = make_list("947108");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

office_versions = hotfix_check_office_version ();
if ( !office_versions["9.0"] && !office_versions["10.0"] && !office_versions["11.0"]) exit(0, "Office version 9.0, 10.0, or 11.0 not found.");

commons = hotfix_get_officecommonfilesdir();
if ( ! commons ) exit(1, "Failed to get Office Common Files directory.");

port = kb_smb_transport();
if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

share = '';
lastshare = '';
vuln = FALSE;
kb       = '947108';
checkedfiles = make_array();
if (typeof(commons) != 'array')
{
  temp = commons;
  commons = make_array('commonfiles', temp);
}
foreach key (keys(commons))
{
  common = commons[key];

  #VBA 6- C:\Program Files\Common Files\Microsoft Shared\VBA\VBA6\vbe6.dll = 6.5.10.24
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
  vba6 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\VBA\VBA6\vbe6.dll", string:common);
  path = common + "\Microsoft Shared\VBA\VBA6\";
  if (checkedfiles[vba6]) continue;

  if (share != lastshar)
  {
    NetUseDel(close:FALSE);
    r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
    if ( r != 1 ) audit(AUDIT_SHARE_FAIL, share);
  }

  handle = CreateFile (file:vba6, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

  if ( ! isnull(handle) )
  {
    checkedfiles[vba6] = 1;
    v = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
    if ( ! isnull(v) )
    {
      if ( v[0] == 6 &&
      (
        v[1] < 5 ||
        (v[1] == 5 && v[2] < 10 ) ||
        (v[1] == 5 && v[2] == 10 && v[3] < 24 )
      ))
      {
        vuln = TRUE;
        info =
          'Path              : ' + path + '\n' +
          'Installed version : ' + join(v, sep:'.') + '\n' +
          'Fix               : 6.5.10.24';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        break;
      }
    }
  }
}
NetUseDel();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:"TRUE");
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
