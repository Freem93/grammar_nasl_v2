#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23750);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_cve_id("CVE-2005-3051");
  script_bugtraq_id(14925, 21208);
  script_osvdb_id(19639);

  script_name(english:"7-Zip ARJ File Handling Overflow");
  script_summary(english:"Checks version of arj.dll from 7-Zip");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the open source 7-Zip file
archiver and included in third-party products such as Knownsoft's
Turbo Searcher.

The version of this software installed on the remote host contains a
buffer overflow in its ARJ file handling library that is triggered
when handling an ARJ block greater than 2600 bytes. If an attacker can
trick a user on the affected host into opening a specially crafted ARJ
archive file, he can leverage this issue to execute arbitrary code on
the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-45/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/411522/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=347504" );
  script_set_attribute(attribute:"see_also", value:"http://vuln.sg/turbosearcher330-en.html" );
  script_set_attribute(attribute:"solution", value:
"Either contact the application's vendor for an update or upgrade to
7-Zip 4.27 beta (4.27.0.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


# Connect to the appropriate share.
#if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!smb_session_init()) exit(0);

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
paths =  make_array();
# - 7-Zip itself
prod = "7-Zip";
key = "SOFTWARE\7-Zip";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) paths[prod] = value[1];

  RegCloseKey(handle:key_h);
}
# - Turbo Searcher
prod = "Turbo Searcher";
key = "SOFTWARE\Classes\folder\shellex\ContextMenuHandlers\Turbo Searcher";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) clsid = value[1];

  RegCloseKey(handle:key_h);

  if (!isnull(clsid))
  {
    key = "SOFTWARE\Classes\CLSID\" + clsid + "\InprocServer32";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value)) paths[prod] = ereg_replace(pattern:"^(.+)\\[^\\]+\.dll", replace:"\1", string:value[1]);

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
if (max_index(keys(paths)) == 0) {
  NetUseDel();
  exit(0);
}


# Check the version of 'arj.dll' in each product.
info = "";
foreach prod (keys(paths))
{
  # Determine the version from the DLL itself.
  path = paths[prod];
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Formats\arj.dll", string:path);
  NetUseDel(close:FALSE);

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
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Check the version number.
  if (!isnull(ver))
  {
    fix = split("4.27.0.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        info += "  " + path + "\Formats\arj.dll (file version=" + version + ')\n';
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Issue a report if any vulnerable files were found.
if (info)
{
    report = string(
      "The following files are affected :\n",
      "\n",
      info
    );
  security_hole(port:port, extra: report);
}

# Clean up.
NetUseDel();
