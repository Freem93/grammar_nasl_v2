#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26185);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/10/08 14:57:50 $");

  script_cve_id("CVE-2007-4607", "CVE-2009-4663");
  script_bugtraq_id(25467, 36440);
  script_osvdb_id(38335, 59939);
  script_xref(name:"CERT", value:"281977");
  script_xref(name:"EDB-ID", value:"4328");
  script_xref(name:"EDB-ID", value:"9705");

  script_name(english:"EasyMail SMTP Object ActiveX Control Multiple Buffer Overflows");
  script_summary(english:"Checks version of EasyMail SMTP Object control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"EasyMail Objects, a set of COM objects for supporting email 
protocols, is installed on the remote Windows host.  It may have been 
bundled with a third-party application, such as Oracle Document 
Capture, Earthlink internet access software, Borland Caliber RM 
Client, and FrontRange Heat.

The SMTP component of the version of this control installed on the
remote host reportedly contains multiple buffer overflows involving 
the AddAttachment and SubmitToExpress methods that could lead to 
arbitrary code execution on the affected system.  Successful 
exploitation requires, though, that an attacker trick a user on the
affected host into visiting a specially crafted web page.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526440/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Either disable its use from within Internet Explorer by setting its
kill bit or remove it completely.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Document Capture 10g ActiveX Control Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");

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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');


# Locate the file used by the controls.
clsids = make_list(
  "{4610E7BF-710F-11D3-813D-00C04F6B92D0}",     # Borland Caliber
  "{68AC0D5F-0424-11D5-822F-00C04F6BA8D9}"
);

info = "";
installs = 0;

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }

  if (!file) continue;

  installs++;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (isnull(version))
  {
    activex_end();
    audit(AUDIT_VER_FAIL, file);
  }

  if (version == '') version = 'unknown';

  # And check it.
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += 
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version + '\n';
  }
}
activex_end();
if (!installs) exit(0, 'None of the affected CLSIDs were found on the remote host.');


# Report findings.
if (info)
{
  # At this point, we want to know how many *vulnerable* installs there are.
  installs = max_index(split(info)) / 4;

  if (report_paranoia > 1)
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bit was set' +
        '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
    else
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bits were set' +
        '\nfor the controls\' CLSIDs because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
  }
  else
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    else
      report = info +
        '\n' +
        '\nMoreover, their kill bits are not set so they are accessible via' +
        '\nInternet Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
  exit(0);
}
else 
{
  if (installs == 1) exit(0, 'One of the controls is installed but its kill bit is set.');
  else exit(0, 'The controls are installed but their kill bits are set.');
}
