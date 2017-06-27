#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83487);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2015-1831");
  script_osvdb_id(121713);

  script_name(english:"Apache Struts 2.3.20 Incorrect Default Exclude Pattern");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses a Java
framework that contains incorrect default exclude patterns.");
  script_set_attribute(attribute:"description", value:
"The remote web server is using Apache Struts version 2.3.20. It is,
therefore, affected by an issue where the default exclude patterns are
incorrect when using default settings. This allows a remote attacker
to impact the internal application's state.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-024.html");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.20.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

fix = "2.3.20.1";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (ver_compare(ver:version, fix:'2.3.20', strict:FALSE) == 0)
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
