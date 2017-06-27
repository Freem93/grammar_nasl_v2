#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67129);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 14:50:16 $");

  script_osvdb_id(94009);
  script_xref(name:"EDB-ID", value:"25714");

  script_name(english:"SAS Integration Technologies Client ActiveX Stack Buffer Overflow");
  script_summary(english:"Checks version of ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an ActiveX control installed that is affected by
a stack-based buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The version of the SAS Integration Technologies Client installed on
the remote host is affected by a stack-based buffer overflow condition
in the 'SASspk.dll' ActiveX control due to improper validation of
user-supplied input to the RetrieveBinaryFile() function via the
'bstFileName' parameter. An unauthenticated, remote attacker can
exploit this, via a crafted file, to cause a denial of service or the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5142.php");
  script_set_attribute(attribute:"see_also", value:"http://support.sas.com/kb/49/961.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sas:sas_integration_technologies");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
clsid = '{DDF47362-6319-11D4-87C0-00C04F48BC53}';

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

# limit check to 9.x branches
if(version !~ "^9\.[23]\d{2}\.")
  exit(0, 'The control is not affected since it is version '+version+'.');

info = '';
fixed_version = '9.320.0.13135';

killbit = activex_get_killbit(clsid:clsid);

if (killbit == -1)
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_killbit', -1);
}

rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
activex_end();

if(isnull(rc))
  audit(AUDIT_FN_FAIL, 'activex_check_fileversion');

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
  else audit(AUDIT_ACTIVEX, version);
}
