#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96484);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/13 17:29:26 $");

  script_cve_id("CVE-2016-6110");
  script_bugtraq_id(95306);
  script_osvdb_id(149661);
  script_xref(name:"IAVA", value:"2017-A-0038");

  script_name(english:"IBM Spectrum Protect Client VM Backup INCLUDE.VMTSMVSS Option Credentials Disclosure");
  script_summary(english:"Checks the version of IBM Spectrum Protect Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Spectrum Protect Client installed on the remote
host is 7.1.x prior to 7.1.6.4. It is, therefore, affected by an
information disclosure vulnerability due to the application exposing
obfuscated VMware vCenter User ID and Password information during the
VM backup process using the INCLUDE.VMTSMVSS option whenever
application tracing is enabled with the VMTSMVSS flag. A local
attacker can exploit this to disclose credential information.

Note that IBM Spectrum Protect was formerly known as IBM Tivoli
Storage Manager in releases prior to version 7.1.3.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21996198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect Client version 7.1.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl", "tivoli_storage_manager_client_installed_linux.nbin");
  script_require_keys("installed_sw/Tivoli Storage Manager Client", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Tivoli Storage Manager Client';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
package = install['Package'];
port = NULL;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (version =~ '^7\\.1\\.' && ver_compare(ver:version, fix:'7.1.6.4', minver:'7.1', strict:FALSE) == -1) fix = '7.1.6.4';

if (isnull(fix)) audit(AUDIT_INST_VER_NOT_VULN, app);

if (get_kb_item("SMB/Registry/Enumerated") && empty_or_null(package)) package = "N/A";
if (get_kb_item("SMB/Registry/Enumerated"))
  port = 445;
else
  port = 0;

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix     +
  '\n  Package           : ' + package +
  '\n';
security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
