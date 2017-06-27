#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58512);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/05/23 15:38:26 $");

  script_cve_id("CVE-2012-0358");
  script_bugtraq_id(52482);
  script_osvdb_id(80042);
  script_xref(name:"CERT", value:"339177");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr00165");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120314-asaclient");

  script_name(english:"Cisco AnyConnect Portforwarder ActiveX Control Initialization Parameter Parsing Buffer Overflow");
  script_summary(english:"Checks if kill bit has been set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control with a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of the Cisco AnyConnect
Portforwarder ActiveX control installed that contains a buffer
overflow in its initialization parameters.  A remote attacker could
exploit this by tricking a user into viewing a specially crafted HTML
document, resulting in arbitrary code execution."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120314-asaclient
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a73cd1ec");
  script_set_attribute(
    attribute:"solution",
    value:
"Set the kill bit for the affected ActiveX control.  Refer to
cisco-sa-20120314-asaclient for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{B8E73359-3422-4384-8D27-4EA1B4C01232}';

# Determine if the control is installed.
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '"+clsid+"' is not defined on the remote host.");
}

# Get its version if possible
version = activex_get_fileversion(clsid:clsid);
info = '';

if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info +=
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file + '\n';
  if (version)
    info += '  Installed version : ' + version + '\n';
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

  if (report_verbosity > 0)
    security_hole(port:kb_smb_transport(), extra:report);
  else
   security_hole(kb_smb_transport());

  exit(0);
}
else exit(0, "The control is installed, but its kill bit is set.");
