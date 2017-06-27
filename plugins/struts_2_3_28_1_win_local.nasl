#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90773);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2016-3081", "CVE-2016-3082", "CVE-2016-3087");
  script_bugtraq_id(87327);
  script_osvdb_id(137435, 137436, 139234);

  script_name(english:"Apache Struts 2.x < 2.3.28.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is 2.x
prior to 2.3.28.1. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists, related to chained
    expressions, when Dynamic Method Invocation (DMI) is
    enabled. An unauthenticated, remote attacker can exploit
    this, via a crafted expression, to execute arbitrary
    code. (CVE-2016-3081)

  - A flaw exists in XSLTResult due to a failure to
    sanitize user-supplied input to the 'location' parameter
    when determining the location of an uploaded stylesheet.
    An unauthenticated, remote attacker can exploit this,
    via a request to a crafted stylesheet, to execute
    arbitrary code. (CVE-2016-3082)

  - A flaw exists that is triggered when dynamic method
    invocation is enabled while using the REST plugin. A
    remote attacker can exploit this, via a specially
    crafted expression, to execute arbitrary code.
    (CVE-2016-3087)
    
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-031.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-032.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-033.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-23281.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.28.1 or later. Alternatively,
apply the workarounds referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts REST Plugin With Dynamic Method Invocation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

fix = "2.3.28.1";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

# Versions 2.3.20.3 and 2.3.24.3 are not affected
if (version == "2.3.20.3" || version == "2.3.24.3")
  audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);


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

  security_report_v4(
    extra    : report,
    port     : port,
    severity : SECURITY_HOLE
  );
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
