#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36103);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2009-1350");
  script_bugtraq_id(34400);
  script_osvdb_id(53351);
  script_xref(name:"Secunia", value:"34574");

  script_name(english:"Novell NetIdentity Agent < 1.2.4 Arbitrary Pointer De-reference Code Execution");
  script_summary(english:"Checks version of xtagent.exe");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host allows remote execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The 'xtagent.exe' program included with the version of Novell's
NetIdentity Agent installed on the remote Windows host contains an
arbitrary pointer de-reference vulnerability. Using specially crafted
RPC messages over the 'XTIERRPCPIPE' named pipe, an attacker who can
establish a valid IPC$ connection can leverage this issue to execute
arbitrary code with system privileges on the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-016/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2009/Apr/52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.novell.com/Download?buildid=6ERQGPjRZ8o~"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to NetIdentity Agent 1.2.4, build 1.2.612 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20);

 script_set_attribute(attribute:"patch_publication_date", value:"2009/04/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Make sure the affected service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    services &&
    "XTAgent" >!< services &&
    "Novell XTier Agent Services" >!< services
  ) exit(0);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
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


# Find the agent's location.
file = NULL;

key = "SOFTWARE\Novell\NetIdentity\SharedDLLs";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    value = RegEnumValue(handle:key_h, index:i);
    if (strlen(value[1]) && value[1] =~ "xtagent\.exe$")
    {
      file = value[1];
      break;
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(0);
}


# Grab the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("1.2.4.5", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], " Build ", ver[3]);

        report = string(
          "\n",
          "  File    : ", file, "\n",
          "  Version : ", version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
