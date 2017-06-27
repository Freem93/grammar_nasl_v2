#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81493);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/25 14:15:04 $");

  script_cve_id("CVE-2014-4817");
  script_bugtraq_id(71109);
  script_osvdb_id(114775);

  script_name(english:"Tivoli Storage Manager Server Unauthorized Backup File Displacement");
  script_summary(english:"Checks the version of Tivoli Storage Manager Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability which allows users to
perform unauthorized actions.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Storage Manager
server that is affected by a vulnerability that allows unauthorized
users to trigger backup operations that can cause previously backed up
files to be rolled off.

Note that this plugin does not check for the presence of any
workarounds.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21686874");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch according to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager", "Settings/ParanoidReport");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod = "IBM Tivoli Storage Manager";

install = get_single_install(app_name:prod, port:port, exit_if_unknown_ver:TRUE);

version = install["version"];

fix = '';

if(version =~ "^6\.3\.[0-5](\.|$)" && ver_compare(ver:version, fix:'6.3.5.100', strict:FALSE) == -1)
  fix = '6.3.5.100';
else if(version =~ "^7\.1\.[01](\.|$)" && ver_compare(ver:version, fix:'7.1.1.100', strict:FALSE) == -1)
  fix = '7.1.1.100';

if(fix != '')
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(port:port,extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
