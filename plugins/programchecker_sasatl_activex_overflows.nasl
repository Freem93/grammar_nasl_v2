#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25344);
  script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2007-2987",
    "CVE-2007-3076",
    "CVE-2007-3703",
    "CVE-2007-3984"
 );
  script_bugtraq_id(
    24217,
    24274,
    24377,
    24380,
    24382,
    24848,
    25025
 );
  script_osvdb_id(36046, 36714, 36715, 37707);
  script_xref(name:"CERT", value:"603529");
  script_xref(name:"EDB-ID", value:"4049");
  script_xref(name:"EDB-ID", value:"4050");
  script_xref(name:"EDB-ID", value:"4170");
  script_xref(name:"EDB-ID", value:"4177");
  script_xref(name:"EDB-ID", value:"4214");

  script_name(english:"ProgramChecker sasatl.dll ActiveX Control Multiple Overflows");
  script_summary(english:"Checks for ProgramChecker ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the ProgramChecker ActiveX control
from Zenturi, a set of tools for examining programs running on a PC.

The version of this ActiveX control on the remote host reportedly
contains multiple vulnerabilities. A remote attacker may be able to
leverage these issues to execute arbitrary code, run arbitrary
programs, or delete arbitrary files on the remote host subject to the
privileges of the current user.");
  # http://moaxb.blogspot.com/2007/05/moaxb-30-zenturi-programchecker-activex.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7053afc");
 script_set_attribute(attribute:"solution", value:
"Disable the use of this ActiveX control from within Internet Explorer
by setting its kill bit.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Zenturi ProgramChecker ActiveX Control Arbitrary File Download');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/30");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:zenturi:zenturi_programchecker");
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
include("global_settings.inc");
include("smb_func.inc");


# Connect to the appropriate share.

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

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


# Check whether it's installed.
file = NULL;

clsids = make_list(
  "{048313BB-3B82-47A8-8164-533F1D7C7C9D}",
  "{0FA0B4FF-1A6F-4D89-995C-29FFD33F4EE0}",
  "{41A5D8DB-EA47-4DE9-B249-1F55738FEA20}",
  "{59DBDDA6-9A80-42A4-B824-9BC50CC172F5}",
  "{66C7B32A-9642-41A4-BCF7-A166D1547770}",
  "{6754F588-E262-42D2-A6BC-3BB400ACFEED}",
  "{7D6B5B24-FC7E-11D1-9288-00104B885781}",
  "{A364AF35-0CDF-41E8-8F3B-E0E55E15EBA1}"
);
foreach clsid (clsids)
{
  key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) file = value[1];

    RegCloseKey(handle:key_h);
  }
  if (!isnull(file)) break;
}


# If it is...
if (file)
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
    info = NULL;

    # Check the compatibility flags for the control.
    foreach clsid (clsids)
    {
      key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{" + clsid +  "}";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      flags = NULL;
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
        if (!isnull(value)) flags = value[1];

        RegCloseKey(handle:key_h);
      }

      # There's a problem if the kill bit isn't set.
      if (isnull(flags) || flags != 0x400) info += '    ' + clsid + '\n';
    }

    if (info)
      report = string(
        "According to the registry, the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "and accessible via Internet Explorer using the following CLSID(s) :\n",
        "\n",
        info
      );
  }

  if (report)
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
