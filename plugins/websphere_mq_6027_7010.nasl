#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57709);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/08 15:44:53 $");

  script_cve_id("CVE-2009-0896");
  script_bugtraq_id(35170);
  script_osvdb_id(55061);

  script_name(english:"IBM WebSphere MQ 6.x < 6.0.2.7 / 7.x < 7.0.1.0 Queue Manager Buffer Overflow RCE");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service installed that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere MQ server installed on the remote Windows host is
version 6.x prior to 6.0.2.7 or version 7.x prior to 7.0.1.0. It is,
therefore, affected by a buffer overflow flaw in the queue manager. A
remote, unauthenticated attacker, by submitting a specially crafted
request, can exploit this to execute arbitrary code in the context of
the application.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386826");
  script_set_attribute(attribute:"solution", value:"Upgrade to WebSphere MQ 6.0.2.7 / 7.0.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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
  "^6\.0\." , "6.0.2.7",
  "^7\.0\." , "7.0.1.0"
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
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
