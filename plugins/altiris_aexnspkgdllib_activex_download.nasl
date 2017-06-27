#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41062);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/06/06 20:52:31 $");

  script_cve_id("CVE-2009-3028");
  script_bugtraq_id(36346);
  script_osvdb_id(57893);
  script_xref(name:"Secunia", value:"36679");

  script_name(english:"Altiris Altiris.AeXNSPkgDL.1 ActiveX Control DownloadAndInstall() Method Arbitrary Code Execution");
  script_summary(english:"Checks for the control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows execution
of arbitrary code."  );
  script_set_attribute(attribute:"description", value:
"The Altiris.AeXNSPkgDL.1 ActiveX control, a component of Altiris
Deployment Solution, Altiris Notification Server, and Symantec
Management Platform, is installed on the remote Windows host.

The installed version of this control provides an unsafe method, named
'DownloadAndInstall'.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, this issue could be leveraged to
download and execute arbitrary code on the affected system subject
to the user's privileges."  );
  # http://web.archive.org/web/20090924030958/http://trac.metasploit.com/browser/framework3/trunk/modules/exploits/windows/browser/symantec_altirisdeployment_downloadandinstall.rb?rev=7023
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81f3a7d5"
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2009&suid=20090922_00
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01cdad31"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.symantec.com/business/support/index?page=content&id=TECH44885"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Either set the kill bit or apply the vendor's hotfix to upgrade the
control to version 6.0.0.2000 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Altiris Deployment Solution ActiveX Control Arbitrary File Download and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{63716E93-033D-48B0-8A2F-8E8473FD7AC7}';
fixed_version = "6.0.0.2000";


# Locate the file used by the control.
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed as the class id '"+clsid+"' is not defined on the remote host.");
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  exit(1, "Failed to get file version of '"+file+"'.");
}


# And check it.
info = '';

rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file + 
            '\n  Installed version : ' + version_ui + 
            '\n  Fixed version     : ' + fixed_version_ui + '\n';
  }
}
activex_end();


# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version_ui+".");
  else if (rc == TRUE) exit(0, "Version "+version_ui+" of the control is installed, but its kill bit is set.");
  else exit(1, "activex_check_fileversion() failed.");
}
