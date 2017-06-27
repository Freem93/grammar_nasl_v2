#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33762);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2008-3373");
  script_bugtraq_id(30417);
  script_osvdb_id(47212);

  script_name(english:"AVG Anti-Virus Crafted UPX File Handling Divide-by-zero Remote DoS");
  script_summary(english:"Checks AVG version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"AVG Anti-Virus is installed on the remote Windows host.

The version of AVG Anti-Virus installed on the remote host is affected
by a 'UPX' file parsing flaw. An attacker can trigger a divide-by-zero
error by causing the application to process a specially crafted 'UPX'
file, which would result in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/security_advisory_AVG_Antivirus_UPX_DoS.php");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jul/270" );
  script_set_attribute(attribute:"see_also", value:"http://www.grisoft.com/ww.94247" );
  script_set_attribute(attribute:"solution", value:"Upgrade to AVG 8.0.156 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/30");

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
include("global_settings.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

key = "SOFTWARE\AVG\Avg8";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"AvgDir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

if(isnull(path))
{
  # Check older version 7.5
  key = "SOFTWARE\Grisoft\Avg7\config";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"dfncfg");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:"^(.+)\dfncfg\.dat$",replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of the AV.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

if ("AVG8" >< path)
  exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avgfrw.exe", string:path);
else
  exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avgcore.dll", string:path);

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
  fix = split("8.0.0.156", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".",ver[3]);
        report = string(
          "\n",
          "Version ", version, " of AVG Anti-Virus is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
      	security_warning(port:port,extra:report);
      }
      else
      	security_warning(port);
      	break;
    }
    else if (ver[i] > fix[i])
      break;
}
