#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88714);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/28 04:28:40 $");

  script_cve_id("CVE-2015-5209");
  script_bugtraq_id(82550);
  script_osvdb_id(127949);

  script_name(english:"Apache Struts 2.x < 2.3.24.1 Request Parameter 'top' Object Access Handling Remote Manipulation");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by a remote manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote Windows host is
version 2.x prior to 2.3.24.1. It is, therefore, affected by a remote
manipulation vulnerability due to incorrect handling of the 'top'
object. An unauthenticated, remote attacker can exploit this, via a
specially crafted request, to manipulate internal components
and container settings.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-026.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.24.1 or later. Alternatively,
apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("struts_detect_win.nbin");
  script_require_keys("installed_sw/Apache Struts", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Apache Struts";
if (report_paranoia < 2) audit(AUDIT_PARANOID);

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

fix = "2.3.24.1";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (version =~ "^2\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report +=
    '\n  Application       : ' + appname +
    '\n  Physical path     : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
}

if (!isnull(report))
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
