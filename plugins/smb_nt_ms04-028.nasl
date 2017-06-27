#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14724);
 script_version("$Revision: 1.51 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id("CVE-2004-0200");
 script_bugtraq_id(11173);
 script_osvdb_id(9951);
 script_xref(name:"CERT", value:"297462");
 script_xref(name:"MSFT", value:"MS04-028");

 script_name(english:"MS04-028: Buffer Overrun in JPEG Processing (833987)");
 script_summary(english:"Checks for ms04-028 via the registry");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that is vulnerable to
a buffer overrun attack when viewing a JPEG file which could allow an
attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a malformed JPEG
file to a user on the remote host and wait for him to open it using an
affected Microsoft application.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-028");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/09/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl" , "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-028';
kbs = make_list("833987");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


global_var report;

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


if ( hotfix_check_sp(xp:2, win2003:1) > 0 )
{
if ( hotfix_missing(name:"KB833987") > 0 )
	{
	 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_security_hole();
 }
	exit(0);
	}
}

if ( ! thorough_tests ) audit(AUDIT_THOROUGH, code:0);

# Crawl through %ProgramFiles% to get the list of affected files
report = make_list();
function add_file(file, version)
{
 report = make_list(report, file + " (version " + version[0] + "." + version[1] + "." + version[2] + "." + version[3] + ")");
}


function get_dirs(basedir, level)
{
 local_var ret, subdirs, subsub, array;


 if(level > 3)
 	return NULL;

 subdirs = NULL;
 ret = FindFirstFile(pattern:basedir + "\*");
 if(isnull(ret))
 	return NULL;


 array = make_list();

 while ( ! isnull(ret[1]) )
 {
  array = make_list(array, basedir + "\" + ret[1]);
  subsub = NULL;
  if("." >!< ret[1])
  	subsub  = get_dirs(basedir:basedir + "\" + ret[1], level:level + 1);
  if(!isnull(subsub))
  {
  	if(isnull(subdirs))subdirs = make_list(subsub);
  	else	subdirs = make_list(subdirs, subsub);
  }

  ret = FindNextFile(handle:ret);
 }

 if(isnull(subdirs))
 	return array;
 else
 	return make_list(array, subdirs);
}



global_var port;
function list_gdiplus_files()
{
 local_var dir, dirs, gdi_plus_file, num_gdi_plus_files, programfiles, r, share;

 num_gdi_plus_files = 0;

 programfiles = hotfix_get_programfilesdir();
 if ( ! programfiles ) exit(1, "Failed to get the Program Files directory.");

 if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

 dir = ereg_replace(pattern:"^[A-Za-z]:\\(.*)", replace:"\1", string:programfiles);
 share = ereg_replace(pattern:"^([A-Za-z]):\\.*", replace:"\1$", string:programfiles);
 gdi_plus_file = NULL;

 r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
 if ( r != 1 )
 {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
 }
 dirs = get_dirs(basedir:dir, level:0);
 foreach dir (dirs)
   {
    if(ereg(pattern:"\\(gdiplus|mso)\.dll", string:dir, icase:TRUE))
    {
     if(isnull(gdi_plus_file)) gdi_plus_file = make_list(dir);
     else gdi_plus_file = make_list(gdi_plus_file, dir);
     num_gdi_plus_files ++;
     if (num_gdi_plus_files >= 10 )
     {
      return gdi_plus_file;
     }
    }
   }
  return(gdi_plus_file);
}

function CheckVersion(file)
{
 local_var i, handle, v;
 handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if(!isnull(handle))
 {
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( ! v ) return 0;
  if ( egrep(pattern:"gdiplus\.dll", icase:TRUE, string:file) )
   {
     # Older than 5.x or 5.1
     if ( v[0] < 5 || v[0] == 5 && v[1] < 1 ) add_file(file:file, version:v);
     # < 5.1.310.1355
     else if ( v[0] == 5 && v[1] == 1 && ( v[2] < 3102 || (v[2] == 3102 && v[3] < 1355 ))) add_file(file:file, version:v);
     # < 5.2.3790.136
     else if ( v[0] == 5 && v[1] == 2 && ( v[2] < 3790 || (v[2] == 3790 && v[3] < 136  ))) add_file(file:file, version:v);
     # < 6.0.3264.0
     else if ( v[0] == 6 && v[1] == 0 && v[2] < 3264 ) add_file(file:file, version:v);
   }
   else if ( egrep(pattern:"mso\.dll", icase:TRUE, string:file) )
   {
     # Older than 10.0.6714
     if ( v[0] < 10 || (v[0] == 10 && v[1] == 0 && v[2] < 6714 )) add_file(file:file, version:v);
   }
 }
}


#
# Here we go
#


port = kb_smb_transport();
login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

files = list_gdiplus_files();
if(!isnull(files))
 {
  foreach f (files)
  {
   if ( "\Macromedia\" >!< f ) CheckVersion(file:f);
  }
}


NetUseDel();

flag = 0;
foreach file (report)
{
 flag ++;
 str += file + '\n';
}


kb       = '833987';

if ( flag > 0 )
{
 report = string (
   "The following files need to be updated :\n\n",
   str
 );
 hotfix_add_report(report, bulletin:bulletin, kb:kb);
 {
 set_kb_item(name:"SMB/Missing/MS04-028", value:TRUE);
 hotfix_security_hole();
 }
}
