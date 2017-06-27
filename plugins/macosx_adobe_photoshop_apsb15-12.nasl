#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84404);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/14 16:30:50 $");

  script_cve_id(
    "CVE-2015-3109",
    "CVE-2015-3110",
    "CVE-2015-3111",
    "CVE-2015-3112"
  );
  script_bugtraq_id(
    75240,
    75242,
    75243,
    75245
  );
  script_osvdb_id(
    123352,
    123353,
    123354,
    123355
  );

  script_name(english:"Adobe Photoshop CC Multiple Vulnerabilities (APSB15-12) (Mac OS X)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Mac OS X host
is prior or equal to CC 2014 15.2.2 (2014.2.2). It is, therefore,
affected by the following vulnerabilities :

  - An unspecified memory corruption flaw exists due to not
    properly validating user-supplied input. An attacker can
    exploit this to execute arbitrary code. (CVE-2015-3109)

  - A integer overflow flaw exists in the GIF parser due to
    not properly handling a GIF file with an invalid
    ImageLeftPosition value. An attacker can exploit this to
    corrupt memory or execute arbitrary code.
    (CVE-2015-3110)

  - A heap-based overflow flaw exists in the PNG parser due
    to not properly handling a PNG file in which the CHUNK
    structure has an oversized length value. An attacker can
    exploit this to corrupt memory or execute arbitrary code.
    (CVE-2015-3111)

  - A memory corruption flaw exists due to not properly
    validating user-supplied input when handling a PDF
    file containing an embedded JPEG with an oversized
    field value. An attacker can exploit this to corrupt
    memory or execute arbitrary code. (CVE-2015-3112)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb15-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC 2015 16.0 (2015.0.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
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
if ("CC" >!< product)
  exit(0, "Only Adobe Photoshop CC is affected.");

path    = install['path'];
version = install['version'];

if (ver_compare(ver:version, fix:'15.2.2', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 16.0';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app + " CC", version);
