#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49707);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2010-3189");
  script_bugtraq_id(42717);
  script_osvdb_id(67561);
  script_xref(name:"EDB-ID", value:"14878");

  script_name(english:"Trend Micro Internet Security Pro UfProxyBrowserCtrl ActiveX extSetOwner Function Arbitrary Code Execution");
  script_summary(english:"Checks version of the UfProxyBrowserCtrl control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that allows execution
of arbitrary code."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The UfProxyBrowserCtrl ActiveX control, a component of Trend Micro
Internet Security Pro 2010 installed on the remote Windows host,
reportedly has an issue in its 'extSetOwner()' function that allows a
remote attacker to run arbitrary code via an invalid address that is
dereferenced as a pointer. 

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary code on the affected system subject to the user's
privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-165/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2010/Aug/287"
  );
   # https://web.archive.org/web/20110912140455/https://esupport.trendmicro.com/pages/Hot-Fix-UfPBCtrldll-is-vulnerable-to-remote-attackers.aspx
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?46d8999a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply the hot fix referenced in Trend Micro's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Trend Micro Internet Security Pro 2010 ActiveX extSetOwner() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trendmicro:internet_security");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


clsid = '{15DBC3F9-9F0A-472E-8061-043D9CEC52F0}';
fixed_version = "17.50.0.1695";


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
            '\n  Installed version : ' + version + 
            '\n  Fixed version     : ' + fixed_version + '\n';
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
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version+".");
  else if (rc == TRUE) exit(0, "Version "+version+" of the control is installed, but its kill bit is set.");
  else exit(1, "activex_check_fileversion() failed.");
}
