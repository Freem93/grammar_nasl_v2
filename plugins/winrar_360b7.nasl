#
#  (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(22072);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2006-3845");
  script_bugtraq_id(19043);
  script_osvdb_id(27379);

  script_name(english:"WinRAR LHA Filename Handling Buffer Overflows");
  script_summary(english:"Check the version of WinRAR");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is suffers from two
buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows.

The version of WinRAR installed on the remote host is affected by two
stack-based buffer overflows when processing LHA files with specially-
crafted filenames. Successful exploitation of either issue enables an
attacker to execute arbitrary code subject to the privileges of the
current user.");
 script_set_attribute(attribute:"see_also", value:"http://www.hustlelabs.com/advisories/04072006_rarlabs.pdf");
 script_set_attribute(attribute:"see_also", value:"http://www.rarlab.com/rarnew.htm" );
 script_set_attribute(attribute:"solution", value:"Upgrade to WinRAR version 3.6.0 beta 7 (3.60.7.0) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/19");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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


# Get some info about the install.
exe = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) exe = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe2,
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

  # There's a problem if the version is before 3.60.7.0
  if (!isnull(ver))
  {
    if (
      ver[0] < 3 ||
      (
        ver[0] == 3 &&
        (
          ver[1] < 60 ||
          (ver[1] == 60 && ver[2] < 7)
        )
      )
    )
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of WinRAR is installed as :\n",
        "  ", exe, "\n"
      );
      security_hole(port:port, extra: report);
    }
  }
}


# Clean up.
NetUseDel();
