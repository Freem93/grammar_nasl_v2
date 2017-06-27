#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48407);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2010-1527", "CVE-2010-3105");
  script_bugtraq_id(42576);
  script_osvdb_id(67410, 67411);
  script_xref(name:"Secunia", value:"40805");

  script_name(english:"Novell iPrint Client < 5.44 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Novell iPrint Client version older than 5.44 is installed on the
remote host. Such versions are reportedly affected by multiple remote
code execution vulnerabilities:

  - A buffer overflow was discovered in how iPrint client
    handles the 'call-back-url' parameter value for a
    'op-client-interface-version' operation where the
    'result-type' parameter is set to 'url'.

  - An uninitialized pointer vulnerability in ienipp.ocx
    was discovered and allows an attacker to exploit an
    issue where the uninitialized pointer is called and
    the process jumps to an address space controllable
    by the attacker.");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-08");
  script_set_attribute(attribute:"see_also",value:"http://secunia.com/secunia_research/2010-104/");
  script_set_attribute(attribute:"see_also",value:"http://download.novell.com/Download?buildid=H-2-uHNc5-A~");
  script_set_attribute(attribute:"see_also",value:"http://www.novell.com/support/viewContent.do?externalId=7006679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell iPrint Client 5.44 or later.

Note that there is no fix available for Novell iPrint Client 4.x
branch so users should consider upgrading to 5.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell iPrint Client ActiveX Control call-back-url Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
  create_disposition:OPEN_EXISTING
);
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
  fixed_version_ui = "5.44";
  version = ver[0] + "." + ver[1] + ver[2];
  if (ver_compare(ver:ver, fix:'5.4.4.0') == -1)
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
  else exit(0, ""+(share-'$')+":"+dll+"' version "+version+" is installed and hence not vulnerable.");
}
else exit(1, "Can't get the file version of '"+(share-'$')+":"+dll+"'.");
