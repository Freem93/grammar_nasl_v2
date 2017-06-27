#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99370);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2017-3004");
  script_bugtraq_id(97559);
  script_osvdb_id(155274);
  script_xref(name:"IAVB", value:"2017-B-0043");

  script_name(english:"Adobe Photoshop CC 17.x < 17.0.2 / 18.x < 18.1 PCX File Handling Arbitrary Code Execution (APSB17-12) (macOS)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote macOS or Mac
OS X host is 17.x prior to 17.0.2 (2015.5.2) or 18.x prior to 18.1
(2017.1.0). It is, therefore, affected by an arbitrary code execution
vulnerability due to a memory corruption issue that is triggered when
handling PCX files. An unauthenticated, remote attacker can exploit
this, by convincing a user to open a specially crafted PCX file, to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 17.0.2 (2015.5.2) / 18.1
(2017.1.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os) audit(AUDIT_OS_NOT, 'Mac OS X');

app = 'Adobe Photoshop';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
if ("CC" >!< product)
  exit(0, "Only Adobe Photoshop CC is affected.");

path    = install['path'];
version = install['version'];

# version 18.x < 18.1 Vuln
if ( version =~ "^18\." )
  fix = '18.1';
# 17.x < 17.0.2 Vuln
else if ( version =~ "^17\." )
  fix = '17.0.2';
else
  audit(AUDIT_NOT_INST, app + " 17.x / 18.x");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Product           : ' + product +
           '\n  Path              : ' + path +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix;

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app + " CC", version);
