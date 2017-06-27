#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87766);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/09 22:38:11 $");

  script_cve_id("CVE-2015-8571", "CVE-2015-8572");
  script_bugtraq_id(79800, 79803);
  script_osvdb_id(
    131478,
    131479,
    131480,
    131481, 
    131482,
    131483
  );
  script_xref(name:"ZDI", value:"ZDI-15-615");
  script_xref(name:"ZDI", value:"ZDI-15-616");
  script_xref(name:"ZDI", value:"ZDI-15-617");
  script_xref(name:"ZDI", value:"ZDI-15-618");
  script_xref(name:"ZDI", value:"ZDI-15-619");
  script_xref(name:"ZDI", value:"ZDI-15-620");

  script_name(english:"Autodesk Design Review < 2013 Hotfix 2 Multiple RCE");
  script_summary(english:"Checks the version of Autodesk Design Review.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Design Review installed on the remote Windows
host is prior to 2013 Hotfix 2. It is, therefore, affected by the
following vulnerabilities :

  - An integer overflow condition exists due to improper
    handling of BMP images. A remote attacker can exploit
    this, via a crafted 'biClrUsed' value in a BMP file, to
    trigger a buffer overflow, resulting in the execution of
    arbitrary code. (CVE-2015-8571)

  - Multiple buffer overflow conditions exist due to
    improper validation of user-supplied input. A remote
    attacker can exploit this, via crafted data in BMP, FLI,
    and GIF files, to execute arbitrary code.
    (CVE-2015-8572)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-615/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-616/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-617/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-618/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-619/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-620/");
  # http://knowledge.autodesk.com/support/design-review/downloads/caas/downloads/content/autodesk-design-review-2013-hotfix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d427536b");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix 2 to Autodesk Design Review 2013.

Note that older versions will need to be updated to 2013 before
applying the hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:design_review");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "autodesk_dr_installed.nbin");
  script_require_keys("installed_sw/Autodesk Design Review");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");

app = "Autodesk Design Review";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed = '13.2.0.82';

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, path, version);
