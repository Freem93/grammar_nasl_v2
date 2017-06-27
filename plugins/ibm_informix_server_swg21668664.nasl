#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80476);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:43:28 $");

  script_cve_id("CVE-2013-6747");
  script_bugtraq_id(65156);
  script_osvdb_id(102556);

  script_name(english:"Informix Server GSKit 7.x <= 7.0.4.47 / 8.0.50.x <= 8.0.50.13 X.509 Certificate Chain DoS");
  script_summary(english:"Checks version of Informix Server and GSKit.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Informix server ships with a version of IBM's Global
Security kit (GSKit) library that is affected by a denial of service
vulnerability. A remote attacker can exploit this issue via malformed
X.509 certificate chain to cause the host to become unresponsive.

Note that this plugin only checks the version of IBM Informix Server
and GSKit. It does not check for the presence of any workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21668664");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Informix server or apply the correct GSKit patch per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_gskit_installed.nasl", "ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM GSKit", "installed_sw/IBM Informix Dynamic Server");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("install_func.inc");
include('misc_func.inc');

ids_app = 'IBM Informix Dynamic Server';
ids_install = get_single_install(app_name:ids_app, exit_if_unknown_ver:TRUE);

ids_ver   = ids_install['version'];
ids_path  = ids_install['path'];

ids_fix   = NULL;
gsk_regex = NULL;
gsk_fix = NULL;

item = eregmatch(pattern: "[cC]([0-9]+)([^0-9]|$)",
                 string: ids_ver);
c_num = 0;
if (!isnull(item[1])) c_num = int(item[1]);

# 11.50 (currently no fix for 11.50 branch)
if (ids_ver =~ "^11\.50($|[^0-9])")
{
  ids_fix     = "None available. Upgrade GSKit.";
  gsk_regex = "^7\.";
  gsk_fix   = '7.0.4.48';
}
# 11.70 (currently no fix for 11.70 branch)
else if (ids_ver =~ "^11\.70($|[^0-9])")
{
  ids_fix     = "None available. Upgrade GSKit.";
  gsk_regex = "^8\.0\.50\.";
  gsk_fix   = "8.0.50.17";
}
# 12.10 < 12.10.xC3
else if (ids_ver =~ "^12\.10($|[^0-9])" && c_num < 3)
{
  ids_fix     = "12.10.xC4";
  gsk_regex = "^8\.0\.50\.";
  gsk_fix   = "8.0.50.17";
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, ids_app, ids_ver, ids_path);

# Check GSKit version if Informix is not patched
gsk_app = "IBM GSKit";

# We don't bother to exit if we can't detect any GSKit installations
gsk_installs = get_installs(app_name:gsk_app);
gsk_report   = NULL;
gsk_vuln     = 0;

foreach gsk_install (gsk_installs[1])
{
  gsk_ver  = gsk_install['version'];
  gsk_path = gsk_install['path'];

  if (gsk_ver =~ gsk_regex &&
      ver_compare(ver:gsk_ver, fix:gsk_fix, strict:FALSE) == -1)
  {
    gsk_report +=
      '\n  Path              : ' + gsk_path +
      '\n  Installed version : ' + gsk_ver  +
      '\n  Fixed version     : ' + gsk_fix  + '\n';

    gsk_vuln++;
  }
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n' + 'The install of ' + ids_app + ' is vulnerable :' +
    '\n' +
    '\n' + '  Path              : ' + ids_path +
    '\n' + '  Installed version : ' + ids_ver  +
    '\n' + '  Fixed version     : ' + ids_fix  +
    '\n';

  if (!isnull(gsk_report))
  {
    instance = " instance "; is_are   = " is ";

    if (gsk_vuln > 1) {instance = " instances "; is_are = " are ";}

    report +=
      '\nAlso, the following vulnerable'+instance+'of '+gsk_app+is_are+'installed on the'+
      '\nremote host :' +
      '\n' +
      gsk_report;
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
