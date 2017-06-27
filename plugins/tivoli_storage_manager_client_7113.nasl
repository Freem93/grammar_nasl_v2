#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81813);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/12 17:36:04 $");

  script_cve_id("CVE-2014-6185");
  script_bugtraq_id(72868);
  script_osvdb_id(117930);

  script_name(english:"IBM Tivoli Storage Manager Client DSO Local Privilege Escalation");
  script_summary(english:"Checks the version of IBM Tivoli Storage Manager Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Linux host is affected by
a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager Client installed on the
remote Linux host is potentially affected by a local privilege
escalation vulnerability. A local attacker, using a crafted DSO file,
could exploit this vulnerability to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21695715");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager Client 6.3.2.3 / 6.4.2.2 / 7.1.1.3
or later, or apply the workaround.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed_linux.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Tivoli Storage Manager Client", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Workaround - remove 'dsmtca' module
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure the host is not Windows
if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app = 'Tivoli Storage Manager Client';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
package = install['Package'];

fix = NULL;

if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.1.3', strict:FALSE) == -1) fix = '7.1.1.3';
else if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.2.2', strict:FALSE) == -1) fix = '6.4.2.2';
else if (version =~ '^6\\.1\\.' && ver_compare(ver:version, fix:'6.3.2.3', strict:FALSE) == -1) fix = '6.3.2.3';

if (isnull(fix)) audit(AUDIT_PACKAGE_NOT_AFFECTED, package);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix     +
    '\n  Package           : ' + package +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
