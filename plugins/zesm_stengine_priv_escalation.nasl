#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29896);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");

  script_cve_id("CVE-2007-5665");
  script_bugtraq_id(27146);
  script_osvdb_id(39995);

  script_name(english:"Novell ZENworks ESM Security Client STEngine Privilege Escalation");
  script_summary(english:"Checks version of STEngine.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
local privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"Novell ZENworks Endpoint Security Management (ESM) Security Client is
installed on the remote host. It provides a centrally-managed,
policy-based firewall for enterprise computers.

The version of this software on the remote host dynamically generates
various scripts which are then executed by the application in a
directory to which local users have write access and also will run
them using the file 'cmd.exe' in that directory. A local user can
reportedly leverage this issue to execute arbitrary code on the
affected host with SYSTEM level privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44bb005f");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/42");
 script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=5Y6xbs-OKLE~" );
 script_set_attribute(attribute:"solution", value:"Upgrade to ZENworks ESM Security Client 3.5.0.82 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
path = NULL;

key = "SYSTEM\CurrentControlSet\Services\Eventlog\Application\STEngine";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"EventMessageFile");
  if (!isnull(value))
  {
    dll = value[1];
    path = ereg_replace(pattern:"^(.+)\\\[^\]+\.dll$", replace:"\1", string:dll);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of STEngine.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\STEngine.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
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
  fix = split("3.5.0.82", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of STEngine.exe is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
