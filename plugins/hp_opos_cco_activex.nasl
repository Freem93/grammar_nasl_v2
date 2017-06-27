#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81824);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id(
    "CVE-2014-7888",
    "CVE-2014-7889",
    "CVE-2014-7890",
    "CVE-2014-7891",
    "CVE-2014-7892",
    "CVE-2014-7893",
    "CVE-2014-7894",
    "CVE-2014-7895",
    "CVE-2014-7897",
    "CVE-2014-7898"  
  );
  script_bugtraq_id(72969);
  script_osvdb_id(
    119191,
    119192,
    119193,
    119194,
    119195,
    119196,
    119197,
    119198,
    119189,
    119190
  );

  script_name(english:"HP OPOS CCO Drivers RCE Vulnerabilities");
  script_summary(english:"Checks for multiple HP OPOS CCO ActiveX controls.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HP OLE Point of Sale (OPOS) Common Control Objects (CCO) drivers
installed on the remote host are prior to version 1.13.003. They are,
therefore, potentially affected by unspecified vulnerabilities in the
following ActiveX controls :

  - OPOSCashDrawer.ocx
  - OPOSCheckScanner.ocx
  - OPOSLineDisplay.ocx
  - OPOSMICR.ocx
  - OPOSMSR.ocx
  - OPOSPOSKeyboard.ocx
  - OPOSPOSPrinter.ocx
  - OPOSScanner.ocx
  - OPOSToneIndicator.ocx

A remote attacker could exploit these vulnerabilities to execute
arbitrary code.

Note that, according to the advisory, only HP Point of Sale PCs are
affected by these vulnerabilities.");

  # http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04583185
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31d7796a");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-094/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-095/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-096/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-097/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-098/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-099/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-100/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-101/");
  script_set_attribute(attribute:"see_also", value:"http://monroecs.com/oposccos_history.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to OPOS CCO version 1.13.003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:ole_point_of_sale_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
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

# Only affects HP Point of Sale PCs
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("SMB/Registry/Enumerated");

clsids = make_list(
  '{CCB90102-B81E-11D2-AB74-0040054C3719}', #OPOSLineDisplay.ocx
  '{CCB90042-B81E-11D2-AB74-0040054C3719}', #OPOSCashDrawer.ocx
  '{CCB90152-B81E-11D2-AB74-0040054C3719}', #OPOSPOSPrinter.ocx
  '{CCB90112-B81E-11D2-AB74-0040054C3719}', #OPOSMICR.ocx
  '{CCB90232-B81E-11D2-AB74-0040054C3719}', #OPOSCheckScanner.ocx
  '{CCB90122-B81E-11D2-AB74-0040054C3719}', #OPOSMSR.ocx
  '{CCB90142-B81E-11D2-AB74-0040054C3719}', #OPOSPOSKeyboard.ocx
  '{CCB90202-B81E-11D2-AB74-0040054C3719}', #OPOSToneIndicator.ocx
  '{CCB90182-B81E-11D2-AB74-0040054C3719}'  #OPOSScanner.ocx
);

activex_fix = "1.13.003";

app_name = "OPOS CCO Drivers";

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

info = "";
patched = make_list();
ver_fail = make_list();

# Check all files for version
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (empty_or_null(file)) continue;

  version = activex_get_fileversion(clsid:clsid);
  if (empty_or_null(version)) ver_fail = make_list(ver_fail, file);

  if (ver_compare(ver:version, fix:activex_fix, strict:FALSE) == -1)
  {
    info += '\n  Product name      : ' + app_name +
            '\n  Class identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : ' + activex_fix +
            '\n';
  }
  else patched = make_list(patched, file + ' version ' + version);
}
activex_end();

if (info)
{
  report = 'Discovered vulnerable ActiveX control(s) :\n' +
    info +
    '\n' +
    'Please note that Nessus did not check whether the kill bit was\n' +
    'set for the control(s) because of the Report Paranoia setting\n' +
    'in effect when this scan was run.\n';

  if (report_verbosity > 0)
  {
    security_warning(port:kb_smb_transport(), extra:report);
    exit(0);
  }
  else
  {
    security_warning(kb_smb_transport());
    exit(0);
  }
}
else
{
  if (!empty(ver_fail)) audit(AUDIT_VER_FAIL, join(ver_fail, sep:" and "));
  if (max_index(patched) > 0)
    exit(0, 'The following file(s) for ' + app_name + ' are installed and not affected:\n  '
      + join(patched, sep:'\n  '));
  audit(AUDIT_ACTIVEX_NOT_FOUND, join(clsids, sep:' and '));
}
