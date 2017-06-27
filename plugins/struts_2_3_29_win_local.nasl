#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91812);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/28 21:03:38 $");

  script_cve_id(
    "CVE-2016-0785",
    "CVE-2016-4430",
    "CVE-2016-4431",
    "CVE-2016-4433",
    "CVE-2016-4436",
    "CVE-2016-4438",
    "CVE-2016-4465"
  );
  script_bugtraq_id(
    91275,
    91277,
    91278,
    91280,
    91281,
    91282,
    91284
  );
  script_osvdb_id(
    135892,
    140022,
    140023,
    140024,
    140025,
    140026,
    140027
  );

  script_name(english:"Apache Struts 2.x < 2.3.29 Multiple Vulnerabilities");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is 2.x
prior to 2.3.29. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists due to
    erroneously performing double OGNL evaluation of
    attribute values assigned to certain tags. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary code.
    (CVE-2016-0785)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to improper validation of session tokens. An
    unauthenticated, remote attacker can exploit this, via a
    malicious OGNL expression, to bypass token validation
    and perform an XSRF attack. (CVE-2016-4430)

  - Multiple input validation issues exists that allow
    internal security mechanisms to be bypassed, allowing
    the manipulation of a return string which can be used to
    redirect users to a malicious website. This affects both
    the default action method the 'getter' action method.
    (CVE-2016-4431, CVE-2016-4433)

  - An unspecified flaw exists that is triggered during the
    cleanup of action names. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    payload, to perform unspecified actions. (CVE-2016-4436)

  - A remote code execution vulnerability exists in the REST
    plugin due to improper handling of OGNL expressions. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted OGNL expression, to execute
    arbitrary code. (CVE-2016-4438)

  - A denial of service vulnerability exists in URLValidator
    due to improper handling of form fields. An
    unauthenticated, remote attacker can exploit this, via a
    crafted URL, to overload the server when performing
    validation on the URL. (CVE-2016-4465)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-035.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-036.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-037.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-038.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-039.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-040.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-041.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2329.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.29 or later. Alternatively,
apply the workarounds referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

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
get_install_count(app_name:app, exit_if_zero:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

fix = "2.3.29";
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
    xsrf     : TRUE
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
