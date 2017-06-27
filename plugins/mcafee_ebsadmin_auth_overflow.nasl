#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29900);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2008-0127");
  script_bugtraq_id(27197);
  script_osvdb_id(40220);

  script_name(english:"McAfee E-Business Server Authentication Packet Remote Overflow");
  script_summary(english:"Checks file version of EBS.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"McAfee E-Business Server, an enterprise tool for digitally encrypting
and signing electronic files, is installed on the remote host.

The version of this software installed on the remote host fails to
properly handle over-sized authentication packets sent to its
administration interface, generally TCP port 1718. An unauthenticated,
remote attacker may be able to leverage this issue to crash the
affected service or even execute arbitrary code on the remote host
with LOCAL SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.infigo.hr/en/in_focus/advisories/INFIGO-2008-01-06");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/94" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/101" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/542/614472_f.SAL_Public.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to McAfee E-Business Server version 8.5.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:e-business_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Figure out where the installer recorded information about it.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "McAfee E-Business Server" >< prod)
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0);


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

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


# Find out where it was installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of EBS.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\EBS.exe", string:path);
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
  fix = split("8.5.3.108", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2]);

      report = string(
        "McAfee E-Business Server version ", version, " is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_hole(port:port, extra:report);

      break;
    }
    else if (ver[i] > fix[i])
      break;
}
