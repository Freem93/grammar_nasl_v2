#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25167);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2007-0940");
 script_bugtraq_id(23782);
 script_osvdb_id(34397);
 script_xref(name:"MSFT", value:"MS07-028");
 script_xref(name:"CERT", value:"866305");

 script_name(english:"MS07-028: Vulnerability in CAPICOM Could Allow Remote Code Execution (931906)");
 script_summary(english:"Determines the version of CAPICOM.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the CAPICOM library
(Cryptographic API Component Object Model) that is subject to a flaw
that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to set up a rogue web
site and lure a victim on the remote host into visiting it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-028");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for CAPICOM.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:capicom");
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

bulletin = 'MS07-028';
kbs = make_list("931906");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain);
if (rc != 1)
{
  NetUseDel();
  exit( 1, 'Could not login with supplied credentials' );
}


# Determine where it's installed.
keys = make_list(
	"SOFTWARE\\Classes\\CAPICOM.Certificates\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.1\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.2\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.3\\CLSID"
	);

foreach key (keys)
{
 rc = NetUseAdd(share:"IPC$");
 if (rc != 1)
 {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
 }

 # Connect to remote registry.
 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (isnull(hklm))
 {
   NetUseDel();
   audit(AUDIT_REG_FAIL);
 }


 value = NULL;

 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    value = value[1];
    RegCloseKey(handle:key_h);

    key_h = RegOpenKey(handle:hklm, key:'SOFTWARE\\Classes\\CLSID\\' + value + "\InprocServer32", mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value))
        value = value[1];
    }
    else
       value = NULL;
    }
    RegCloseKey(handle:key_h);
  }

  RegCloseKey(handle:hklm);
  NetUseDel (close:FALSE);

  if (!isnull(value))
  {
    value = str_replace(string:value, find:'"', replace:"");

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value);
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:value);

    r = NetUseAdd(share:share);
    if ( r != 1 )
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL,share);
    }
    v = get_kb_item("SMB/FileVersions" + tolower(str_replace(string:dll, find:'\\', replace:"/")));
    if ( isnull(v) )
    {
      handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

      if ( ! isnull(handle) )
      {
        v = GetFileVersion(handle:handle);
        CloseFile(handle:handle);
      }
    }
    else
    {
      v = split( v, sep:".", keep:FALSE );
      v = make_list( int( v[0] ), int( v[1] ), int( v[2] ), int( v[3] ) );
    }

    if ( !isnull(v) )
    {
      set_kb_item(name:"SMB/FileVersions" + tolower(str_replace(string:dll, find:'\\', replace:"/")), value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
      if (  ( v[0] < 2)  ||
            ( v[0] == 2 && v[1] < 1 ) ||
            ( v[0] == 2 && v[1] == 1 && v[2] == 0 && v[3] < 2 ) )
      {
        version = string(v[0], ".", v[1], ".", v[2], ".", v[3]);
        report = string(  "Information about the vulnerable control :\n",
                          "\n",
                          "  Registry entry : HKLM\\", key, "\n",
                          "  File           : ", value, "\n",
                          "  Version        : ", version, "\n"
                        );
        hotfix_add_report(report, bulletin:'MS07-028', kb:'931906');
        set_kb_item(name:"SMB/Missing/MS07-028", value:TRUE);
        hotfix_security_hole();
        exit( 0 );
      }
    }
  }
  NetUseDel(close:FALSE);
}
NetUseDel();
exit(0, "The host is not affected.");
