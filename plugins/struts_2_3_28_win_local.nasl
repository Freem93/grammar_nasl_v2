#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90153);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/28 21:03:38 $");

  script_cve_id("CVE-2016-0785", "CVE-2016-2162", "CVE-2016-3093");
  script_osvdb_id(135892, 135902, 139233);

  script_name(english:"Apache Struts 2.x < 2.3.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is 2.x
prior to 2.3.28. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists due to
    double OGNL evaluation of attribute values assigned to
    certain tags. An unauthenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2016-0785)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when using
    the I18NInterceptor. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. (CVE-2016-2162)

  - A denial of service vulnerability exists in the
    Object-Graph Navigation Language (OGNL) component due to
    a flaw in the implementation of the cache for stored
    method references. A context-dependent attacker can
    exploit this to block access to arbitrary websites.
    (CVE-2016-3093)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-029.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-030.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-034.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2328.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.28 or later. Alternatively,
apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

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

fix = "2.3.28";
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

  security_report_v4(
    extra    : report,
    port     : port,
    severity : SECURITY_HOLE,
    xss      : TRUE
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
