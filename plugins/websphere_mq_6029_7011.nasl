#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62943);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id("CVE-2010-2637");
  script_bugtraq_id(55521);
  script_osvdb_id(69229);

  script_name(english:"IBM WebSphere MQ 6.x < 6.0.2.9 / 7.x < 7.0.1.1 'userid' and 'password' Information Disclosure");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service installed that does not encrypt
usernames and passwords submitted to web pages.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere MQ server installed on the remote Windows host is
version 6.x prior to 6.0.2.9 or version 7.x prior to 7.0.1.1. It is,
therefore, affected by a security weakness where usernames and
passwords are sent as cleartext in parameter fields, thus allowing a
remote attacker to obtain sensitive information by sniffing the
networking traffic.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007069");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014224");
  script_set_attribute(attribute:"solution", value:"Upgrade to WebSphere MQ 6.0.2.9 / 7.0.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

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
fix      = FALSE;
fixes    = make_array(
  "^6\.0\."    , "6.0.2.9",
  "^7\.0\.1\." , "7.0.1.1"
);

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
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
