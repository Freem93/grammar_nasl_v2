#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78514);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2014-2635",
    "CVE-2014-2636",
    "CVE-2014-2637",
    "CVE-2014-2638"
  );
  script_bugtraq_id(70354, 70356, 70357, 70358);
  script_osvdb_id(113000, 113001, 113002, 113003);
  script_xref(name:"HP", value:"emr_na-c04454636-1");
  script_xref(name:"IAVB", value:"2014-B-0136");
  script_xref(name:"HP", value:"HPSBMU03110");
  script_xref(name:"HP", value:"SSRT101584");
  script_xref(name:"HP", value:"SSRT101585");
  script_xref(name:"HP", value:"SSRT101586");
  script_xref(name:"HP", value:"SSRT101587");

  script_name(english:"HP Sprinter Remote Code Execution");
  script_summary(english:"Checks the ActiveX controls.");

  script_set_attribute(attribute:"synopsis", value:
"A manual software testing tool installed on the remote host is
affected by multiple unspecified remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Sprinter installed on the remote Windows host has
multiple unspecified remote code execution vulnerabilities, which are
related to the 'TTF16.ocx' ActiveX control.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04454636
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5da9ad16");
  script_set_attribute(attribute:"solution", value:"Apply HP Sprinter Service Pack 12.01 Patch 1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sprinter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sprinter_installed.nbin", "smb_hotfixes.nasl");
  script_require_keys("installed_sw/HP Sprinter", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = "HP Sprinter";
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

verui = install['display_version'];

# Locate the file used by the controls.
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

info = NULL;

clsids = make_list(
  '{B0475003-7740-11D1-BDC3-0020AF9F8E6E}',
  '{B0475031-7740-11D1-BDC3-0020AF9F8E6E}'
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    ver = activex_get_fileversion(clsid:clsid);

    if (!ver) ver = "unknown";

    if (activex_get_killbit(clsid:clsid) == 0)
    {
      info +=
        '\n  Class identifier  : ' + clsid +
        '\n  Filename          : ' + file +
        '\n  Installed version : ' + ver +
        '\n';
    }
  }
}

activex_end();

if (info)
{
  port = kb_smb_transport();

  report =
    '\n' + appname + ' ' + verui + ' is installed on the remote host and is using the' +
    '\n' + 'following vulnerable ActiveX control(s):' +
    '\n' + info +
    '\n' + 'Moreover, their kill bits are not set so they are accessible via Internet' +
    '\n' + 'Explorer.' +
    '\n';

  if (report_verbosity > 0)
    security_warning(port:port, extra:report);
  else
    security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, verui);
