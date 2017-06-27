#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79860);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2014-7809", "CVE-2015-5169");
  script_bugtraq_id(71548, 76625);
  script_osvdb_id(115217, 126679);

  script_name(english:"Apache Struts 2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is using a version of Struts 2 that is affected
by multiple vulnerabilities :

  - A cross-site request forgery vulnerability exists due to
    the token generator failing to adequately randomize the
    token values. An attacker can exploit this issue by
    extracting a token from a form and then predicting the
    next token value that will be used to secure form
    submissions. By convincing a victim to visit a specially
    crafted form, the predicted token value can be used to
    force an action for a logged in user. Note that this
    vulnerability can only be exploited when the <s:token/>
    tag is used within a form. (CVE-2014-7809)

  - A cross-site scripting vulnerability exists due to
    improper validation of input passed via the 'Problem
    Report' screen when using debug mode. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in the context of a user's browser session.
    (CVE-2015-5169)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-023.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-4423");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("struts_detect_win.nbin");
  script_require_keys("installed_sw/Apache Struts", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Apache Struts";

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

fix = "2.3.20";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^2\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
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
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
