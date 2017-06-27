#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31122);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2008-0620", "CVE-2008-0621");
  script_bugtraq_id(27613);
  script_osvdb_id(41126, 41127);
  script_xref(name:"Secunia", value:"28786");

  script_name(english:"SAPlpd < 6.29 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of SAPlpd.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"SAP GUI is installed on the remote host. It is the GUI client
component used with SAP ERP / SAP R/3 enterprise resource planning
software.

The installation of SAP GUI on the remote host includes a print
server, SAPlpd, that is affected by several denial of service and
buffer overflow vulnerabilities. An unauthenticated, remote attacker
can leverage these issues to crash the affected service or to execute
arbitrary code on the affected host subject to the privileges under
which it operates.");
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/saplpdz-adv.txt");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/27" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/34" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SAPlpd version 6.29 or later by updating to SAP GUI for
Windows version 7.10 Patchlevel 6 / 6.30 Patchlevel 30 / 6.20
Patchlevel 72 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SAP SAPLPD 6.28 Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/20");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:saplpd");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sapgui");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\SAP\SAP Shared";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"SAPsysdir");
  if (!isnull(value)) path = value[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of .
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SAPlpd\SAPlpd.exe", string:path);
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
  fix = split("6.29", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1]);
        report = string(
          "\n",
          "Version ", version, " of SAPlpd is installed under :\n",
          "\n",
          "  ", path, "\\SAPlpd\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
