#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99369);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2017-3004", "CVE-2017-3005");
  script_bugtraq_id(97553, 97559);
  script_osvdb_id(155274, 155275);
  script_xref(name:"IAVB", value:"2017-B-0043");

  script_name(english:"Adobe Photoshop CC 17.x < 17.0.2 / 18.x < 18.1 Multiple Vulnerabilities (APSB17-12)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote Windows host
is 17.x prior to 17.0.2 (2015.5.2) or 18.x prior to 18.1 (2017.1.0).
It is, therefore, affected by multiple vulnerabilities :

  - A memory corruption issue exists due to improper
    handling of PCX files. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted PCX file, to execute arbitrary code.
    (CVE-2017-3004)

  - An unquoted search path flaw exists that allows an
    attacker to elevate privileges via a malicious
    executable in the root path. (CVE-2017-3005)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 17.0.2 (2015.5.2) / 18.1
(2017.1.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Photoshop";
install  = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

product_name = install['Product'];
if ("CC" >!< product_name)
  exit(0, "Only Adobe Photoshop CC is affected.");

ver    = install['version'];
path   = install['path'];
ver_ui = install['display_version'];

# version 18.x < 18.1 Vuln
if ( ver =~ "^18\." )
  fix = '18.1';
# 17.x < 17.0.2 Vuln
else if ( ver =~ "^17\." )
  fix = '17.0.2';
else
  audit(AUDIT_NOT_INST, app_name + " 17.x / 18.x");

if (ver_compare(ver: ver, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  report = '\n  Product           : ' + product_name +
           '\n  Path              : ' + path +
           '\n  Installed version : ' + ver_ui +
           '\n  Fixed version     : ' + fix +
           '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver_ui, path);
