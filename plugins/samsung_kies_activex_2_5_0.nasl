#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65612);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/20 16:51:15 $");

  script_cve_id(
    "CVE-2012-3806",
    "CVE-2012-3807",
    "CVE-2012-3808",
    "CVE-2012-3809",
    "CVE-2012-3810"
  );
  script_bugtraq_id(55936);
  script_osvdb_id(86500, 86501);
  script_xref(name:"EDB-ID", value:"22007");

  script_name(english:"Samsung Kies < 2.5.0.12094_27_11 Multiple ActiveX Control Vulnerabilities");
  script_summary(english:"Checks version of ActiveX Control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has ActiveX controls that are affected by multiple
vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Samsung Kies ActiveX controls installed on the remote
host is affected by multiple vulnerabilities :

  - A vulnerability in GetDataTable() method in
    'DCAPARAGONGM.dll' is affected by a NULL pointer
    dereference that could be used to perform a denial of
    service of the program.  (CVE-2012-3806)

  - Multiple vulnerabilities exist affecting CmdAgentLib in
    'CmdAgent.dll'. An attacker may be able to exploit this
    issue to gain elevated privileges. (CVE-2012-3807,
    CVE-2012-3808 CVE-2012-3809, CVE-2012-3810)");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23099");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samsung Kies 2.5.0.12094_27_11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samsung:kies");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

clsids = make_array('{1FA56F8D-A66E-4ABD-9BC9-6F61469E59AD}', NULL,
                    '{7650BC47-036D-4d5b-95B4-9D622C8D00A4}', '1.0.0.23',
                    '{C668B648-A2BD-432C-854F-C8C0A275E1F1}', NULL);

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

info = "";
info2 = "";
installs = 0;
vuln =0;
ver_fail = TRUE;

foreach clsid (keys(clsids))
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }
  if (!file) continue;

  installs++;

  version = activex_get_fileversion(clsid:clsid);
  if (isnull(version))
  {
    activex_end();
    audit(AUDIT_VER_FAIL, file);
  }

  if ( version == '') continue;

  if (!isnull(clsids[clsid]))
  {
    if (ver_compare(ver:version, fix:clsids[clsid]) == -1)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
      {
        vuln++;
        info += '\n  Class identifier  : ' + clsid +
                '\n  Filename          : ' + file +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : ' + clsids[clsid] + '\n';
      }
    }
    else info2 += '\n' + file + " version " + version + " is installed and not affected.";
  }
  else if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    vuln++;
    info += '\n  Class identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version + '\n';
  }
}
activex_end();
if (installs==0) exit(0, 'None of the affected CLSIDs were found on the remote host.');

port = kb_smb_transport();
# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    if (vuln == 1)
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bit was set' +
        '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
    else
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bits were set' +
        '\nfor the controls\' CLSIDs because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
  }
  else
  {
    if (vuln == 1)
      report = info +
        '\n' +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    else
       report = info +
         '\n' +
         '\nMoreover, their kill bits are not set so they are accessible via' +
         '\nInternet Explorer.\n';
  }
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port:port);
  exit(0);
}
else
{
  if (info2) exit(0, info2);
  if (installs == 1) exit(0, 'One of the controls is installed but its kill bit is set.');
  else exit(0, 'The controls are installed but their kill bits are set.');
}
