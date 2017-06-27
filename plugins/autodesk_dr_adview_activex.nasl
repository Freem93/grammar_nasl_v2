#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81318);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/08 20:11:34 $");

  script_cve_id("CVE-2014-9268");
  script_bugtraq_id(71485);
  script_osvdb_id(115478);
  script_xref(name:"ZDI", value:"ZDI-14-402");

  script_name(english:"Autodesk Design Review AdView.AdViewer ActiveX Control RCE");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the AdView.AdViewer ActiveX control,
distributed with Autodesk Design Review, that is affected by a remote
code execution vulnerability due to improper parsing of DWF files. An
unauthenticated, remote attacker can exploit this, via a specially
crafted file or website, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-402/");
  # https://knowledge.autodesk.com/support/design-review/downloads/caas/downloads/content/autodesk-design-review-2013-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?737f5f11");
  script_set_attribute(attribute:"solution", value:
"Apply the 2013 hotfix.

Note that older versions will need to be updated to 2013 before
applying the hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review_2008");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review_2009");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review_2010");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review_2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review_2012");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review:2013");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "autodesk_dr_installed.nbin");
  script_require_keys("installed_sw/Autodesk Design Review");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

app = "Autodesk Design Review";

get_install_count(app_name:app, exit_if_zero:TRUE);

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

clsid = "{a662da7e-ccb7-4743-b71a-d817f6d575df}";

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

ver = activex_get_fileversion(clsid:clsid);
if (isnull(ver))
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

activex_end();

fixed = '13.1.0.82';

if (ver_compare(ver:ver, fix:fixed, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  report = NULL;

  if (report_verbosity > 0)
  {
    report =
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, file, ver);
