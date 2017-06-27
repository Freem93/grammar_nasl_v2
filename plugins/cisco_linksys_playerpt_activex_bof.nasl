#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60107);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_cve_id("CVE-2012-0284");
  script_bugtraq_id(54588);
  script_osvdb_id(80297, 84309);
  script_xref(name:"EDB-ID", value:"18641");
  script_xref(name:"Secunia", value:"48543");

  script_name(english:"Cisco Linksys PlayerPT ActiveX Control SetSource() Multiple Overflows");
  script_summary(english:"Checks if control's kill bit is set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco Linksys PlayerPT ActiveX Control is installed on the remote
Windows host.  The installed version of the control is affected by the
following buffer overflow vulnerabilities in the SetSource() method :

  - The 'base64string' argument is not properly sanitized.
    (EBD-ID #18641)

  - The 'sURL' argument is not properly sanitized if the
    'sFrameType' argument is set to 'mpeg'.
    (CVE-2012-0284)

By tricking a victim into visiting a specially crafted page, an
attacker may be able to execute arbitrary code on the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Mar/109");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-25/");
  script_set_attribute(
    attribute:"solution",
    value:
"Set the kill bit for the control as there is no fix at the time of
this writing."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-998");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Linksys PlayerPT ActiveX Control SetSource sURL Argument Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:linksys_playerpt_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Determine if the control is installed.
clsid = '{9E065E4A-BD9D-4547-8F90-985DC62A5591}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version) version = 'unknown';

info = '';
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info += '\n  Class identifier  : ' + clsid +
          '\n  Filename          : ' + file +
          '\n  Installed version : ' + version +
          '\n';
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
else exit(0, "The control is installed, but its kill bit is set.");
