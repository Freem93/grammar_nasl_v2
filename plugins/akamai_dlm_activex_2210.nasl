#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25038);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-1891", "CVE-2007-1892");
  script_bugtraq_id(23522);
  script_osvdb_id(34323, 34324);
  script_xref(name:"CERT", value:"120241");

  script_name(english:"Akamai Download Manager ActiveX Control < 2.2.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Download Manager ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Download Manager ActiveX control
from Akamai, which helps users download content.

The version of this ActiveX control on the remote host reportedly
contains two stack-based buffer overflow vulnerabilities. A remote
attacker may be able to leverage these issues to execute arbitrary
code on the remote host subject to the privileges of the current user.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Apr/473" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/465908/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:"Upgrade to version 2.2.1.0 or later of the control.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/17");

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


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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


# Find the CLSID.
clsid = NULL;

key = "SOFTWARE\Classes\MANAGER.DLMCtrl.1\CLSID";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) clsid = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(clsid))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Now locate the file used by the control.
file = NULL;
flags = NULL;

key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}
if (report_paranoia < 2 && file)
{
  # Check the compatibility flags for the control.
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value)) flags = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(0);
}


# Check the version of the control.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:ocx,
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
  fix = split("2.2.1.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "\n",
        "Version ", version, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "It uses the CLSID :\n",
        "\n",
        "  ", clsid, "\n"
        );

      if (report_paranoia > 1)
        report = string(
          report,
          "\n",
          "Note, though, that Nessus did not check whether the kill bit was\n",
          "set for the control's CLSID because of the Report Paranoia setting\n",
          "in effect when this scan was run.\n"
        );
      else if (isnull(flags) || flags != 0x400)
        report = string(
          report,
          "\n",
          "Moreover, its kill bit is not set so it is accessible via Internet\n",
          "Explorer.\n"
        );
      if (report)
      {
        if (report_verbosity) security_hole(port:port, extra:report);
        else security_hole(port);
      }
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
