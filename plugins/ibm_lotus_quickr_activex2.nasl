#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72586);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/30 21:51:49 $");

  script_cve_id("CVE-2013-6748", "CVE-2013-6749");
  script_bugtraq_id(65191, 65193);
  script_osvdb_id(102597, 102598);

  script_name(english:"Lotus Quickr for Domino qp2.dll ActiveX Control Unspecified Stack Overflow");
  script_summary(english:"Checks version of ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control installed that is affected by a
stack-based buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is an unspecified, stack-based buffer overflow vulnerability in
the Lotus Quickr for Domino qp2.dll ActiveX control.  By tricking a
victim into opening a specially crafted web page, an attacker can
leverage this flaw to potentially execute arbitrary code, subject to
the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-018/");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21662653");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate fix pack per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_quickr_for_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
clsid = '{05D96F71-87C6-11d3-9BE4-00902742D6E0}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_filename');
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
if (version =~ "^8\.5\.1\." && ver_compare(ver:version, fix:'8.5.1.42',
                                           strict:FALSE) == -1)
  fix = '8.5.1.42';

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
