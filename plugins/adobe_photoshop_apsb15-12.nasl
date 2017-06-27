#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84403);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

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

  script_name(english:"Adobe Photoshop CC Multiple Vulnerabilities (APSB15-12)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote host is prior
or equal to CC 2014 15.2.2 (2014.2.2). It is, therefore, affected by
the following vulnerabilities :

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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("installed_sw/Adobe Photoshop");

app_name = "Adobe Photoshop";

install = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

product_name = install['Product'];
if ("CC" >!< product_name)
  exit(0, "Only Adobe Photoshop CC is affected.");

ver = install['version'];
path = install['path'];
ver_ui = install['display_version'];

# version < 15.2.2 Vuln
if (ver_compare(ver: ver, fix: '15.2.2', strict:FALSE) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product_name +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : 16.0 \n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver_ui, path);
