#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23969);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2006-6509", "CVE-2006-6510");
  script_bugtraq_id(21567);
  script_osvdb_id(32280, 32281);

  script_name(english:"SiteKiosk < 6.5.150 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SiteKiosk");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple access bypass vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of SiteKiosk on the
remote host contains an unspecified ActiveX control that is marked as
'safe for scripting' yet exposes two dangerous methods that reading
and downloading of any file from the kiosk. In addition, it fails to
completely sanitize input in its 'skinning' feature before using it to
generate dynamic HTML output. By leveraging either issue, a local user
may be able to view the contents of files on the affected host.

Note that SiteKiosk by default runs with LOCAL SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Dec/232" );
 script_set_attribute(attribute:"see_also", value:"http://www.sitekiosk.com/en-US/SiteKiosk/VersionHistory.aspx" );
 script_set_attribute(attribute:"solution", value:"Upgrade to SiteKiosk version 6.5.150 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/03");

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
key = "SOFTWARE\PROVISIO\SiteKiosk";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path)) {
  NetUseDel();
  exit(0);
}


# Determine the version from the program itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SiteKiosk.exe", string:path);
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
  fix = split("6.5.150.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "\n",
        "Version ", version, " of SiteKiosk is installed under : \n",
        "\n",
        "  ", path, "\n"
      );
      security_warning(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
