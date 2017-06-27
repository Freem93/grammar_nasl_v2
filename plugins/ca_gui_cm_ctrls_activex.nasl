#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67258);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2008-1786");
  script_bugtraq_id(28809);
  script_osvdb_id(44423);
  script_xref(name:"CERT", value:"684883");

  script_name(english:"CA Multiple Products gui_cm_ctrls.ocx ActiveX Control Arbitrary Code Execution");
  script_summary(english:"Checks version of ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control installed that is affected by an
arbitrary code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has the CA gui_cm_ctrls.ocx ActiveX control installed
that is affected by an arbitrary code execution vulnerability due to
insufficient verification of function arguments.  By tricking a user
into opening a specially crafted web page, a remote attacker may be able
to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Apr/180");
  # http://community.ca.com/blogs/casecurityresponseblog/archive/2008/04/16/ca-dsm-gui-cm-ctrls-activex-control-vulnerability.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d0c7846");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch or workaround per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:computer_associates:arcserve_backup_laptops_and_desktops");
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
clsid = '{E6239EB3-E0B0-46DA-A215-CFA9B3B740C5}';

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
if (version =~ "^11\.1\." && ver_compare(ver:version, fix:'11.1.8124.2517',
                                           strict:FALSE) == -1)
  fix = '11.1.8124.2517';
else if (version =~ "^11\.2\.2\." && ver_compare(ver:version, fix:'11.2.2.4332',
                                           strict:FALSE) == -1)
  fix = '11.2.2.4332';
else if (version =~ "^11\.2\.3\." && ver_compare(ver:version, fix:'11.2.3.1896',
                                           strict:FALSE) == -1)
  fix = '11.2.3.1896';
else if (version =~ "^11\.2\.1000\." &&
                                    ver_compare(ver:version, fix:'11.2.1000.17',
                                           strict:FALSE) == -1)
  fix = '11.2.1000.17';
else if (version =~ "^11\.2\.2000\." &&
                                    ver_compare(ver:version, fix:'11.2.2000.4',
                                           strict:FALSE) == -1)
  fix = '11.2.2000.4';

if (fix != '')
{
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
  if (fix == '') exit(0, 'The control is not affected since it is version '+version+'.');
  else audit(AUDIT_ACTIVEX, version);
}
