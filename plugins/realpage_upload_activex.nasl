#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50434);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2010-2584", "CVE-2010-2585");
  script_bugtraq_id(44302);
  script_osvdb_id(68813, 68814);
  script_xref(name:"Secunia", value:"41392");

  script_name(english:"RealPage Module Upload ActiveX Control Multiple Vulnerabilities");
  script_summary(english:"Checks for the RealPage Upload control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The RealPage Module Upload ActiveX control, used with RealPage's
OneSite Property Management Systems software and installed on the
remote Windows host, reportedly is affected by several
vulnerabilities :

  - The 'Upload' method in combination with the
    'SourceFile' and 'DestURL' properties can be abused to
    upload arbitrary files from a user's system to a web
    server. (CVE-2010-2584)

  - By setting a long 'SourceFile' or 'DestURL' property
    value, an attack can trigger a buffer overflow and
    possibly execute arbitrary code. (CVE-2010-2585)"
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-118/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-119/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realpage:module_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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


clsid = '{2C487E1D-7051-453A-BB55-1D435C0666D8}';


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
if (!version)
{
  activex_end();
  exit(1, "Failed to get the file version of '"+file+"'.");
}


# And check it.
info = '';
fixed_version = '1.0.0.10';

killbit = activex_get_killbit(clsid:clsid);

if (killbit == -1)
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_killbit', -1);
}

rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
activex_end();

if (isnull(rc)) audit(AUDIT_FN_FAIL, 'activex_check_fileversion');

if (rc == TRUE)
{
  if (report_paranoia > 1 || killbit == 0)
  {
    info +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}


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
  if (rc == FALSE) exit(0, 'The control is not affected since it is version '+version+'.');
  else audit(AUDIT_ACTIVEX, version);
}
