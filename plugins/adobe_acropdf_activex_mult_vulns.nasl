#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23776);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2006-6027", "CVE-2006-6236");
  script_bugtraq_id(21155, 21338, 21813);
  script_osvdb_id(31057, 31058);

  script_name(english:"Adobe Reader < 8.0 AcroPDF ActiveX Control Multiple Vulnerabilities");
  script_summary(english:"Checks version of AcroPDF ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'AcroPDF' ActiveX control
included with Adobe Reader and Acrobat.

The version of this ActiveX control on the remote host reportedly
exposes several methods that fail to handle malformed arguments. If an
attacker can trick a user on the affected host into visiting a
specially crafted web page, he can leverage these issues to execute
arbitrary code on the host subject to the user's privileges.");

  # http://web.archive.org/web/20100108011317/http://research.eeye.com/html/alerts/zeroday/20061128.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?827c7862");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/453579/100/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb06-20.html" );
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Adobe Reader 8.0 or replace the version of
'AcroPDF.dll' as described in the vendor bulletin referenced above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
clsid = '{CA8A9780-280D-11CF-A24D-444553540000}';
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
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{" + clsid +  "}";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value)) flags = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(file)) {
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
}

# Check the version number.
if (!isnull(ver) && ver[0] == 7 && ver[1] == 0 && ver[2] < 9)
{
  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "The ActiveX control is installed, but Nessus did not check\n",
      "whether it is disabled in Internet Explorer because of the\n",
      "Report Paranoia setting in effect when this scan was run.\n"
    );
  else
  {
    # There's a problem if the kill bit isn't set.
    if (isnull(flags[clsid]) || flags[clsid] != 0x400)
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "Version ", version, " of the control is installed as \n",
          "\n",
          "  ", file, "\n"
        );
      }
      else report = NULL;
    }
  }
  if (report) security_hole(port:port, extra:report);
}


# Clean up.
NetUseDel();
