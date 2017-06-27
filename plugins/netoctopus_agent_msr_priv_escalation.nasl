#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29928);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-5761");
  script_bugtraq_id(27175);
  script_osvdb_id(40106);

  script_name(english:"netOctopus Agent nantsys.sys MSR Write Local Privilege Escalation");
  script_summary(english:"Checks existence of nantsys.sys");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a driver that is affected by a local
privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"netOctopus Agent, an asset management agent, is installed on the
remote host.

The installed version of netOctopus Agent includes a driver, named
'nantsys.sys', that exposes a device interface writable by all local
users, allowing them to read and write arbitrary CPU Model Specific
Registers (MSRs). A local user could leverage this issue to execute
arbitrary code in kernel mode.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=636
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d698705a");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485911/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected driver using the vendor-supplied script referenced
in the advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:motorola:netoctopus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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

key = "SOFTWARE\Netopia\netOctopus\Agent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"AgentPath");
  if (!isnull(value)) path = value[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check if the affected file exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
sys = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nantsys.sys", string:path);
NetUseDel(close:FALSE);

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

# There's a problem if it does.
if (!isnull(fh))
{
  CloseFile(handle:fh);

  report = string(
    "\n",
    "The affected driver is installed as :\n",
    "\n",
    "  ", path, "\\nantsys.sys\n"
  );
  security_hole(port:port, extra:report);
}
NetUseDel();
