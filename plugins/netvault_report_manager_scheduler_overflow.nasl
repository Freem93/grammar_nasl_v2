#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25767);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2007-3911");
  script_bugtraq_id(25068);
  script_osvdb_id(38618, 38619);
  script_xref(name:"TRA", value:"TRA-2007-05");

  script_name(english:"NetVault Report Manager Scheduler File Name Handling Overflow");
  script_summary(english:"Checks version of Server Scheduler");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running NetVault Report Manager, a tool for
monitoring backup reports.

The Server and Client Scheduler components included in the version of
NetVault Report Manager installed on the remote host suffer from a
heap overflow vulnerability that can occur when processing overly long
filename arguments to 'GET' and 'POST' requests. Code execution is
possible under the context of the SYSTEM user.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-05");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-044.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/296" );
  script_set_attribute(attribute:"solution", value:"Upgrade to NetVault Report Manager v3.5 Update 4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bakbone:netvault_reporter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
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


# Make sure it's installed.
exe = NULL;
key = "SYSTEM\CurrentControlSet\Services\USServerSchedulerService";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(value)) exe = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(exe))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:sys,
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
  # nb: 3.5.1.248 is the file version from version 3.5 Update 4.
  fix = split("3.5.1.248", sep:'.', keep:FALSE);
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
