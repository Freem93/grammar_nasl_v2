#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83288);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2014-4771");
  script_bugtraq_id(74326);
  script_osvdb_id(118358);

  script_name(english:"IBM WebSphere MQ 7.0 / 7.1 / 7.5 / 8.0 PCF Query DoS");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service installed that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere MQ server installed on the remote Windows
host is either 7.0 without fix pack 7.0.1.13, 7.1 without fix pack
7.1.0.6, 7.5 without fix pack 7.5.0.5, or 8.0 without fix pack
8.0.0.1. It is,therefore, affected by a denial of service
vulnerability. A remote, authenticated attacker, with access to the
command input queue, can use a crafted PCF query to create an
artificially full reply queue, thus preventing other users from
submitting queries to the system.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21696120");
  script_set_attribute(attribute:"solution", value:"Apply the fix pack provided by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
type     = install['Type'];
fix      = FALSE;
fixes    = make_array(
  "^7\.0\.1\.", "7.0.1.13",
  "^7\.1\.0\.", "7.1.0.6",
  "^7\.5\.0\.", "7.5.0.5",
  "^8\.0\.0\.", "8.0.0.1"
);

# Only server
if (tolower(type) != "server")
  audit(AUDIT_HOST_NOT,app_name+" Server");

# Find the fix for our version
foreach fixcheck (keys(fixes))
{
  if(version =~ fixcheck)
  {
    fix = fixes[fixcheck];
    break;
  }
}

# Version not affected
if(!fix)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(extra:report, port:port);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
