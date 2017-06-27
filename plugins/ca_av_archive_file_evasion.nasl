#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35473);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/06/30 20:19:09 $");

  script_cve_id("CVE-2009-0042");
  script_bugtraq_id(33464);
  script_osvdb_id(53604);

  script_name(english:"CA Antivirus Engine Multiple Scan Evasion");
  script_summary(english:"Checks version of arclib.dll.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by
multiple scan evasion vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Computer Associates (CA) antivirus scan engine installed on the
remote host is affected by multiple scan evasion vulnerabilities due
to a failure to handle certain malformed archive files. An attacker
can exploit this, via crafted archive files, to evade detection by the
scan engine.");
  # http://blog.zoller.lu/2009/01/ca-anti-virus-engine-detection-evasion.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98dd1f65" );
  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=197601
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fcf32b0");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/May/99" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503447/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory to apply the appropriate patch or update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/28");

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

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


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


# Find where it's installed.
path = NULL;

key = "SOFTWARE\ComputerAssociates\ScanEngine\Path";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Engine");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of file Arclib.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Arclib.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  fix = split("7.3.0.15", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
	version = string(ver[0],".",ver[1],".",ver[2],".",ver[3]);
        report = string(
          "\n",
          "Version ", version, " of Arclib.dll is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else
      	security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
