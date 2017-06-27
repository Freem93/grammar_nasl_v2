#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48275);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2010-2990", "CVE-2010-2991");
  script_bugtraq_id(42149,42150);
  script_osvdb_id(66829, 66830);
  script_xref(name:"Secunia", value:"40819");
  script_xref(name:"IAVB", value:"2010-B-0057");
  script_xref(name:"Secunia", value:"40821");

  script_name(english:"Citrix ICA Client Multiple Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks the version of ICA Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix ICA Client installed on the remote host is older
than 12.0.3. Such versions are reportedly affected by the following
remote code execution vulnerabilities:

A vulnerability can be exploited by tricking a user into connecting to
a malicious server, via a malicious '.ICA' file or by other means,
making it possible for an attacker to execute arbitrary code on the
remote client.

Another vulnerability has been identified in the ICA Client ActiveX
Object (ICO) component which can allow an attacker to execute
arbitrary code on the remote client.");

  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX125975");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX125976");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/39");
  script_set_attribute(attribute:"solution", value:"Upgrade to ICA Client 12.0.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:ica_client_for_linux");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:ica_client_for_solaris");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:ica_client_for_windows_mobile");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");
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
  exit(1, "Can't connect to IPC$ share.");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Check whether it's installed.
path = NULL;

key1 = "SOFTWARE\Citrix\ICA Client";
key1_h = RegOpenKey(handle:hklm, key:key1, mode:MAXIMUM_ALLOWED);
if (!isnull(key1_h))
{
  value = RegQueryValue(handle:key1_h, item:"MsiInstallDir");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key1_h);
}

if (isnull(path))
{

  key2 = "SOFTWARE\Citrix\Install\ICA Client";
  key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
  if (!isnull(key2_h))
  {
    value = RegQueryValue(handle:key2_h, item:"InstallFolder");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key2_h);
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Citrix ICA Client is not installed.");
}

# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\wfica32.exe", string:path);
NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
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
else
{
  NetUseDel();
  exit(0, "Failed to open '"+path+"\wfica32.exe'.");
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version = join(ver,sep:".");
  fixed_version = "12.0.3";

  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
      {
        report =
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fixed_version + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
  }

  exit(0, "Citrix ICA Client version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+exe+"'.");
