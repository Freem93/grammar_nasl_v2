#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24712);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2007-0321");
  script_bugtraq_id(22673);
  script_osvdb_id(33532);
  script_xref(name:"CERT", value:"847993");

  script_name(english:"FLEXnet Connect Update Service Agent ActiveX (isusweb.dll) Overflow");
  script_summary(english:"Checks version of Update Service Agent ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"Macrovision FLEXnet Connect, formerly known as InstallShield Update
Service, is installed on the remote host. It is a software management
solution for internally-developed and third-party applications, and
may have been installed as part of the FLEXnet Connect SDK, other
InstallShield software, or by running FLEXnet Connect-enabled Windows
software.

The version of FLEXnet Connect on the remote host includes an ActiveX
control -- Update Service Agent -- that is reportedly affected by a
buffer overflow vulnerability involving its 'Download()' method. If an
attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to execute
arbitrary code on the host subject to the user's privileges.");
 script_set_attribute(attribute:"solution", value:
"Either upgrade to a version of the FLEXnet Connect SDK with installer
version 12.0.0.49974 or later; or, disable the control as described in
the US-CERT advisory referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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


# Check whether it's installed.
clsid = '{E9880553-B8A7-4960-A668-95C68BED571E}';
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
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid +  "";
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


# Determine the version from the control itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # File version from fixed version of the product is 6.0.100.60146.
  if (
    !isnull(ver) &&
    (
      ver[0] < 6 ||
      (
        ver[0] == 6 && ver[1] == 0 &&
        (
          ver[2] < 100 ||
          (ver[2] == 100 && ver[3] < 60146)
        )
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "According to the registry, version ", version, " of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the kill bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else
    {
      # There's a problem if the kill bit isn't set.
      if (isnull(flags) || flags != 0x400)
      {
        report = string(
          "According to the registry, version ", version, " of the vulnerable\n",
          "control is installed as :\n",
          "\n",
          "  ", file, "\n"
        );
      }
    }
    if (report) security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
