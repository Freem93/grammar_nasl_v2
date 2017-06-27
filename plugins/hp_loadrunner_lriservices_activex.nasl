#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69399);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-4801");
  script_bugtraq_id(61445);
  script_osvdb_id(95645);

  script_name(english:"HP LoadRunner lrLRIServices ActiveX Control Code Execution Vulnerability");
  script_summary(english:"Checks for ActiveX Control");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an ActiveX control installed that is affected by
an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has the HP LoadRunner lrLRIServices ActiveX control
installed.  The version of the installed control is potentially
affected by an arbitrary code execution vulnerability in the handling
of input to the output directory mutator.  By tricking a user into 
opening a specially crafted web page, a remote attacker may be able
to execute arbitrary code subject to the privileges of the user
running the affected application.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03862772-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c99066d5");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-209/");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP LoadRunner 11.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
clsid = '{7475E2E2-3268-4B22-BD66-4F350760DBF0}';

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

killbit = activex_get_killbit(clsid:clsid);
activex_end();

if (killbit == -1)
  audit(AUDIT_FN_FAIL, 'activex_get_killbit', -1);

fix = '';
if (ver_compare(ver:version, fix:'11.52.4391.0') < 0)
{
  fix = '11.52.4391.0';
  if (report_paranoia > 1 || killbit == 0)
  {
    info +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
  }
}

# Report findings
if (info)
{
  if (report_paranoia > 1)
  {
    report =
      info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      'set for the control\'s CLSID because of the Report Paranoia setting\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report =
      info +
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
  if (!fix) exit(0, 'The control is not affected since it is version ' + version + '.');
  else audit(AUDIT_ACTIVEX, version);
}
