#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77528);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/10 01:41:19 $");

  script_cve_id("CVE-2014-0876");
  script_bugtraq_id(69261);
  script_osvdb_id(109999);

  script_name(english:"IBM Tivoli Storage Manager Client 6.2.x < 6.2.5.2 / 6.3.x < 6.3.2 / 6.4 < 6.4.1.3 Local Buffer DoS");
  script_summary(english:"Checks the version of the Tivoli Storage Manager Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Windows host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager Client installed on the remote
Windows host is affected by a denial of service vulnerability.

There is an unspecified overflow condition within the Java GUI
configuration wizard and the Preferences Editor. This issue allows a
local attacker to cause a denial of service with the wizard or editor.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tsm_client_gui_local_hang_cve_2014_0876?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a24c7101");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673318");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager Client 6.2.5.2 / 6.3.2 / 6.4.1.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl");
  script_require_keys("installed_sw/Tivoli Storage Manager Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Tivoli Storage Manager Client';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fix = '';

if (version =~ '^5\\.[45]\\.' || version =~ '^6\\.1\\.')
  fix = "Please refer to the vendor's website.";
if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.5.2', strict:FALSE) < 0)
  fix = '6.2.5.2';
if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.2', strict:FALSE) < 0)
  fix = '6.3.2';
if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.1.3', strict:FALSE) < 0)
  fix = '6.4.1.3';

if(fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
