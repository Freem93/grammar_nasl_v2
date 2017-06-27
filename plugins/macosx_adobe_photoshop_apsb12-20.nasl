#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62222);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/14 16:30:50 $");

  script_cve_id("CVE-2012-0275", "CVE-2012-4170");
  script_bugtraq_id(55333, 55372);
  script_osvdb_id(85006, 85437);
  script_xref(name:"EDB-ID", value:"20971");

  script_name(english:"Adobe Photoshop CS6 for Mac Multiple RCE Vulnerabilities (APSB12-20) (Mac OS X)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple remote
code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Mac OS X host
is prior to CS6 13.0.1. It is, therefore, affected by remote code
execution vulnerabilities due to multiple buffer overflows. A remote
attacker, using a crafted file, can exploit these to execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-29/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Photoshop CS6 13.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cs6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("installed_sw/Adobe Photoshop");

app = 'Adobe Photoshop';

install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
if ("CS6" >!< product)
  exit(0, "Only Adobe Photoshop CS6 is affected.");

path    = install['path'];
version = install['version'];

if(
    ver_compare(ver:version, fix:'13.0', strict:FALSE) >= 0 &&
    ver_compare(ver:version, fix:'13.0.1', strict:FALSE) < 0
  )
{
  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 13.0.1';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app + " CS6", version);
