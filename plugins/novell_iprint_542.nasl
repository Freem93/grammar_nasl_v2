#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48364);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2010-3106", "CVE-2010-3107", "CVE-2010-3108", "CVE-2010-3109");
  script_bugtraq_id(42100);
  script_osvdb_id(66958, 66959, 66960 ,66961);
  script_xref(name:"Secunia", value:"40782");

  script_name(english:"Novell iPrint Client < 5.42 Multiple Flaws");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Novell iPrint Client version older than 5.42 is installed on the
remote host. Such versions are reportedly affected by multiple
vulnerabilities :

  - Due to a flaw in nipplib.dll module, it may be possible
    for a remote attacker to delete arbitrary files from
    the remote system via the 'CleanUploadFiles' method
    provided by an ActiveX control. (TPTI-10-05)

  - By passing a specially crafted value to the 'debug'
    parameter in the ActiveX control ienipp.ocx, it may be
    possible for an attacker to trigger a stack-based
    buffer overflow, potentially resulting in arbitrary
    code execution within the context of the user running
    the browser. (TPTI-10-06)

  - Due to improper validation of plugin parameters, it may
    be possible for an attacker to trigger a buffer overflow
    condition resulting in arbitrary code execution within
    the context of the user running the browser.
    (ZDI-10-139)

  - Due to improper validation of plugin parameters, it may
    be possible for an attacker to trigger a stack-based
    buffer overflow, potentially resulting in arbitrary code
    execution within the context of the user running the
    browser. (ZDI-10-140)");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-05");
  script_set_attribute(attribute:"see_also",value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-06");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-10-139");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-10-140");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2010/Aug/65");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2010/Aug/66");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2010/Aug/69");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2010/Aug/70");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=ftwZBxEFjIg~");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell iPrint Client 5.42 or later.

Note that there is no fix available for Novell iPrint Client 4.x
branch so users should consider upgrading to 5.42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell iPrint Client ActiveX Control ExecuteRequest debug Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

winroot = hotfix_get_systemroot();
if (!winroot) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot' KB item is missing.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\nipplib.dll", string:winroot);

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(file:dll,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "The file '"+winroot+"\System32\nipplib.dll' does not exist.");
}


ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  # Version that is not vulnerable.
  fixed_version_ui = "5.42";
  version = ver[0] + "." + ver[1] + ver[2];
  if (ver_compare(ver:ver, fix:'5.4.2.0') == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + winroot + "\System32\nipplib.dll" +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version_ui + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else
   exit(0, ""+(share-'$')+":"+dll+"' version "+version+" is installed and hence not vulnerable.");
}
else exit(1, "Can't get the file version of '"+(share-'$')+":"+dll+"'.");
