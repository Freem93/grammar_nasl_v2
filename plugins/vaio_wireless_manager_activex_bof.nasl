#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60109);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/23 15:38:27 $");

  script_cve_id("CVE-2012-0985");
  script_bugtraq_id(53735);
  script_osvdb_id(82401);
  script_xref(name:"EDB-ID", value:"18958");

  script_name(english:"Sony VAIO Wireless Manager ActiveX Control WifiMan.dll Multiple Buffer Overflows");
  script_summary(english:"Checks version of control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control installed that is
affected by multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Sony VAIO Wireless Manager ActiveX control installed on the
remote Windows host is affected by buffer overflow vulnerabilities in
'SetTmpProfileOption()' and 'ConnectToNetWokrkOption()' in
WifiMan.dll.  By tricking a victim into visiting a specially crafted
page, an attacker may be able to execute arbitrary code on the
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23063");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?051362c9");
  script_set_attribute(attribute:"solution", value:
"Either set the kill bit for the control or upgrade to version 5.7.0
of the control.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sony:vaio_easy_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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
if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

# Determine if the control is installed
clsid = '{92E7DDED-BBFE-4DDF-B717-074E3B602D1B}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, 'activex_get_filename() returned NULL.');
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';
fixed_version = '5.7.0.0';
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}
activex_end();

# Report findings
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      'set for the control\'s CLSID because of the Report Paranoia setting\n' +
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
  if (rc == FALSE) exit(0, 'The control is not affected since it is version '+version+'.');
  else if (rc == TRUE) exit(0, 'Version '+version+' of the control is installed, but its kill bit is set.');
  else exit(1, 'activex_check_fileversion() failed.');
}
