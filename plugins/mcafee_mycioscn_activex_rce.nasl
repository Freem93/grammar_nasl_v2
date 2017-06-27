#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57713);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/04/15 22:06:48 $");

  script_bugtraq_id(51397);
  script_osvdb_id(78310);
  script_xref(name:"EDB-ID", value:"18376");

  script_name(english:"McAfee Security-as-a-Service (SaaS) mcCIOScn.dll ShowReport Method Remote Command Execution");
  script_summary(english:"Checks for the MyCioScan control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that could be abused
to execute arbitrary code remotely."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The myCIOScn.dll ActiveX control, installed on the remote Windows host
as part of McAfee Security-as-a-Service (SaaS) / Total Protection
Service, reportedly does not require authentication before executing
arbitrary commands passed to its 'ShowReport' method. 

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to execute 
arbitrary code on the host subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-12-012"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/521245/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Set the kill bit for the affected control.

Note that McAfee reportedly removed the 'Safe for Scripting'
designation for the control in SaaS Endpoint Protection 5.2.2 in
August 2011 as part of a fix for a related issue and which should
significantly migitate exploitation of this issue.  In addition,
McAfee plans to address the issue completely at some point in the
future by removing the affected code entirely as part of its automatic
patching."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'McAfee SaaS MyCioScan ShowReport Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:saas_endpoint_protection");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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


clsid = '{209EBDEE-065C-11D4-A6B8-00C04F0D38B7}';


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
  exit(0, "The control is not installed as the class id '"+clsid+"' does not exist on the remote host.");
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version) version = "unknown";


# And check it.
info = '';

if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info += '\n  Class identifier  : ' + clsid +
          '\n  Filename          : ' + file + 
          '\n  Installed version : ' + version + '\n';
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
else exit(0, "Version "+version+" of the control is installed, but its kill bit is set.");
