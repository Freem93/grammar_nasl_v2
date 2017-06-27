#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95887);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/20 15:44:33 $");

  script_cve_id("CVE-2016-8738");
  script_bugtraq_id(94657);
  script_osvdb_id(147960);

  script_name(english:"Apache Struts 2.5.x < 2.5.8 URLValidator Form Field Handling Remote DoS");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is
2.5.x prior to 2.5.8. It is, therefore, potentially affected by a
denial of service vulnerability in the URLValidator class due to
improper handling of user-supplied input to the form field. An
unauthenticated, remote attacker can exploit this, via a specially
crafted URL, to overload server processes.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.8");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-044");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.8 or later. Alternatively,
apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

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
get_install_count(app_name:app, exit_if_zero:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

install = get_single_install(app_name : app);
version = install['version'];
path  = install['path'];
appname = install['Application Name'];

min = "2.5.0";
max = "2.5.5";
fix = "2.5.8";
app = "Apache Struts";
report = NULL;

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, ("the " + app + " application, " + appname + ", found at " + path + ","));

if (ver_compare(ver:version, minver:min, fix:max, strict:FALSE) <= 0)
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
    severity : SECURITY_WARNING
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, (app + " 2 application, " + appname + ","), version, path);
