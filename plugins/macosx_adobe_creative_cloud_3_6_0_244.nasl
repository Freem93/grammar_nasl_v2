#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91387);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id("CVE-2016-1034");
  script_bugtraq_id(86001);
  script_osvdb_id(136944);
  script_xref(name:"ZDI", value:"ZDI-16-235");

  script_name(english:"Adobe Creative Cloud <= 3.5.1.209 Arbitrary File Read/Write Vulnerability (Mac OS X)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an
arbitrary file read/write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Mac OS X
host is prior or equal to 3.5.1.209. It is, therefore, affected by a
flaw in the JavaScript API for Creative Cloud Libraries due to an
exposed service. An unauthenticated, remote attacker can exploit this
to read or write arbitrary files on the host file system.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb16-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-235/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 3.6.0.244 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_creative_cloud_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Creative Cloud");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item('Host/MacOSX/Version');
if (!os)
  audit(AUDIT_OS_NOT, 'Mac OS X');

app = 'Creative Cloud';

install=get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['name'];
path    = install['path'];
version = install['version'];

## For Adobe products, we compare the highest affected product, rather
# than the "fixed" version, as there is an ambiguous gap between what
# is considered affected and the fix.
highest_affected = "3.5.1.209";
fix = '3.6.0.244';

if (ver_compare(ver:version, fix:highest_affected, strict:FALSE) <= 0)
{
   items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Adobe " + app, version, path);
