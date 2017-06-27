#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42261);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2009-3522", "CVE-2009-3523", "CVE-2009-3524");
  script_bugtraq_id(36507, 36796, 36888);
  script_osvdb_id(58402, 58403, 58493);
  script_xref(name:"Secunia", value:"36858");

  script_name(english:"avast! Professional Edition < 4.8.1356 Multiple Vulnerabilities");
  script_summary(english:"Checks version of avast! Professional Edition");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running avast! Professional Edition.

The installed version of avast! Professional Edition is potentially
affected by multiple issues :

  - A local privilege escalation vulnerability because the
    'avast4.ini' file is created with insecure permissions
    on
    setup. (CVE-2009-3524)

  - A local privilege escalation vulnerability because the
    'aswMov2.sys' driver fails to sufficiently sanitize
    user-supplied input passed to 'IOCTL'. (CVE-2009-3522)

  - A local privilege escalation vulnerability because the
    'aavmKer4.sys' driver fails to sufficiently sanitize
    user-supplied input passed to 'IOCTL'. (CVE-2009-3523)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507375/30/0/threaded");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506681/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ntinternals.org/ntiadv0904/ntiadv0904.html"
  );
   # http://web.archive.org/web/20100103212313/http://www.avast.com/eng/avast-4-home_pro-revision-history.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0da112c9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to avast! Professional Edition 4.8.1356 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avast:avast_antivirus_professional");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Grab the installation path and product info from the registry.
path = NULL;
prod = NULL;

key = "SOFTWARE\ALWIL Software\Avast\4.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Avast4ProgramFolder");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Product");
  if (!isnull(value)) prod = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

# If its installed...
if (!isnull(path) && prod == "av_pro")
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\aswEngin.dll",string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) exit(1, "Can't open the file '"+path+"\\aswEngin.dll'.");

  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

}

#Clean Up
NetUseDel();

if (!isnull(ver))
{
  version = strcat(ver[0], ".", ver[1], ".", ver[2]);

  #Check the version number.
  fixed_version = "4.8.1356";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      report = '\n' +
'Product           : Avast! Professional Edition\n' +
'Path              : ' + path + '\n' +
'Installed version : ' + version + '\n' +
'Fixed version     : ' + fixed_version + '\n';
      security_hole(port:port, extra:report);
      exit(0);
    }
    else if(ver[i] > fix[i])
    {
      break;
    }
  exit(0, "Avast! Professional Edition version " + version + " is not affected.");
}
