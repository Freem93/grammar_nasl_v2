#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25768);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2007-3026");
  script_bugtraq_id(25046);
  script_osvdb_id(38614);
  script_xref(name:"TRA", value:"TRA-2007-04");

  script_name(english:"Panda AdminSecure Communications Agent < 4.2 Packet Handling Remote Heap Overflow");
  script_summary(english:"Checks version of pagent.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Panda AdminSecure Communications Agent software, which is used for
centralized management of Panda Antivirus, is installed on the remote
Windows host.

The version of Communications Agent on the remote host trusts a
user-supplied length value for a memory allocation when processing
traffic to TCP port 19226 or 19227 by default, resulting in a
heap-based buffer overflow. An unauthenticated, remote attacker can
leverage this issue to execute arbitrary code with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-04");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-041.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/474551/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Communications Agent 4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pandasecurity:panda_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Panda Software";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Panda Administrator [0-9.]+$")
    {
      key2 = key + "\" + subkey + "\PLAgent";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallPath");
        if (!isnull(value)) path = value[1];

        RegCloseKey(handle:key2_h);
      }
    }
    if (!isnull(path)) break;
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of the server.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Pav_Agent\PAgent.exe", string:path);

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
  fix = split("4.2.0.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
