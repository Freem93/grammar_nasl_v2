#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25954);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2007-4220", "CVE-2007-4221");
  script_bugtraq_id(25453, 25454);
  script_osvdb_id(40121, 40123, 40124, 40125);

  script_name(english:"Timbuktu Pro < 8.6.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of tb2pro.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
issues.");
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Timbuktu Pro on the
remote host reportedly is affected by three buffer overflows that can
be exploited without authentication to crash the service or execute
arbitrary code on the affected host with SYSTEM privileges.

In addition, the application also may allow for creation or deletion
of arbitrary files with SYSTEM privileges on the affected host.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e048278");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83c900c6" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Aug/424" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Aug/425" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f33df19c" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Timbuktu Pro for Windows version 8.6.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 22, 119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/30");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Netopia\Timbuktu Pro";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\tb2pro.exe", string:path);
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

# Check the version number.
if (!isnull(ver))
{
  fix = split("8.6.5.1373", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2]);
      report = string(
        "Version ", version, " of Timbuktu Pro is installed under :\n",
        "\n",
        "  ", path
      );
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
