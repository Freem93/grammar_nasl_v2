#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24700);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2007-0320");
  script_bugtraq_id(22672);
  script_osvdb_id(33530, 33531);
  script_xref(name:"CERT", value:"181041");

  script_name(english:"InstallShield InstallFromTheWeb ActiveX Control Multiple Overflows");
  script_summary(english:"Checks version of InstallFromTheWeb ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"InstallFromTheWeb (IFTW), a web-enabled software installation product
from InstallShield, is installed on the remote host.

The version of InstallFromTheWeb on the remote host includes an
ActiveX control that is reportedly affected by multiple and, as yet,
unspecified buffer overflow vulnerabilities. If an attacker can trick
a user on the affected host into visiting a specially crafted web
page, he can leverage these issues to execute arbitrary code on the
host subject to the user's privileges.");
 script_set_attribute(attribute:"solution", value:
"Disable InstallFromTheWeb's ActiveX control as described in the
US-CERT advisory referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/23");

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

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
clsid = '{4E330863-6A11-11D0-BFD8-006097237877}';
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
  CloseFile(handle:fh);

  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "The InstallFromTheWeb control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Nessus did not check, though, whether it is disabled in Internet\n",
      "Explorer because of the Report Paranoia setting in effect when\n",
      "this scan was run.\n"
    );
  else
  {
    # There's a problem if the kill bit isn't set.
    if (isnull(flags) || flags != 0x400)
    {
      report = string(
        "The InstallFromTheWeb control is installed as :\n",
        "\n",
        "  ", file, "\n"
      );
    }
  }
  if (report) security_hole(port:port, extra:report);
}


# Clean up.
NetUseDel();
