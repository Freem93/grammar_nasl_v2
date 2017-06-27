#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94336);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 15:55:08 $");

  script_cve_id("CVE-2016-6795");
  script_bugtraq_id(93773);
  script_osvdb_id(145647);

  script_name(english:"Apache Struts 2.3.2x / 2.3.3x < 2.3.31 Convention Plugin Path Traversal RCE");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is
2.3.2x or 2.3.3x prior to 2.3.30. It is, therefore, affected by a
remote code execution vulnerability in the Convention plugin due to a
flaw that allows traversing outside of a restricted path. An
unauthenticated, remote attacker can exploit this, via a crafted path
traversal request, to execute arbitrary code on the remote server.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-042.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2331.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("struts_detect_win.nbin");
  script_require_keys("installed_sw/Apache Struts");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Apache Struts";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

min = "2.3.20";
fix = "2.3.31";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (ver_compare(ver:version, minver:min, fix:fix, strict:FALSE) == -1)
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
