#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91981);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/12 17:37:29 $");

  script_cve_id("CVE-2016-2894");
  script_bugtraq_id(91534);
  script_osvdb_id(140756);

  script_name(english:"IBM Tivoli Storage Manager Client Symlink Cross-User Information Disclosure");
  script_summary(english:"Checks the version of IBM Tivoli Storage Manager Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Linux host is affected by
a local information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager Client installed on the
remote Linux host is 5.5.x prior to 6.3.2.6, 6.4.x prior to 6.4.3.3,
or 7.1.x prior to 7.1.6. It is, therefore, affected by an information
disclosure vulnerability due to creating temporary files insecurely. A
local attacker can exploit this, via a symlink created during archive
and retrieve actions, to disclose data from arbitrary accounts.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985579");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager Client version 6.3.2.6 / 6.4.3.3 /
7.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed_linux.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Tivoli Storage Manager Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Make sure the host is not Windows
if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app = 'Tivoli Storage Manager Client';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
package = install['Package'];

fix = NULL;

if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.6', strict:FALSE) == -1) fix = '7.1.6';
else if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.3.3', strict:FALSE) == -1) fix = '6.4.3.3';
else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.2.6', strict:FALSE) == -1) fix = '6.3.2.6';
else if (version =~ '^(5\\.5|6\\.[12])\\.') fix = "See Solution.";

if (isnull(fix)) audit(AUDIT_PACKAGE_NOT_AFFECTED, package);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix     +
  '\n  Package           : ' + package +
  '\n';
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
