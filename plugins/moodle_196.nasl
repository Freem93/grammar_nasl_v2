#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47128);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Moodle < 1.9.6 / 1.8.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Moodle.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host is prior to 1.9.6 /
1.8.10. It is, therefore, affected by multiple vulnerabilities :

  - Email addresses are not escaped properly in email
    change confirmation codes. (MDL-20295)

  - When upgrading from a version older than 1.9.0, certain
    tags are not properly escaped. (MDL-19709)

  - It may be possible for certain teachers to perform SQL
    injection attacks while updating the first post in a
    single simple discussion forum. (MDL-20555)

  - Function 'update_record' is affected by a SQL injection
    issue. A registered user could exploit this issue to
    manipulate database queries, resulting in disclosure of
    sensitive information or attacks against the underlying
    database. (MDL-20309)

  - It may be possible for teachers to view student grades
    in all courses even though they do not have teacher
    rights for the course in an overview report. (MDL-20355)

  - An error in ADODB OCI8/MSSQL drivers could allow SQL
    injection (only servers using Oracle and MS SQL
    databases
    are affected).(MDL-19452)");

  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Moodle_1.9.6_release_notes#Security_issues");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Moodle_1.8.10_release_notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle 1.9.6 / 1.8.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
v = install['version'];
install_url = build_url(port:port, qs:dir);

version = '';
build = 0;

if (v =~ "^[0-9.+]+ *\(Build: *[0-9]+\)$")
  regex = "^([0-9.+]+) *\(Build: *([0-9]+)\)$";
else
  regex = "^([0-9.+]+) *.+";

matches = eregmatch(pattern:regex,string:v);
if (matches && matches[1]) version = matches[1];

if(matches[2] && matches[2] =~ "^[0-9]+$") build = matches[2];

if (version !~ "^[0-9.+]+$") exit(1, "Unexpected version found for the "+app+" install at "+ install_url +".");

if (
  version =~ "^(0\..*|1\.[0-7]\+?\..*|1\.([0-9]\+?|8\.[0-8]\+?|8\.9|9\.[0-4]\+?|9\.5)$)" ||
  (
    (version == "1.9.5+" || version == "1.8.9+") &&
    (
      !build ||
      (
        substr(build, 0, 3) < 2009 ||
        (substr(build, 0, 3) == 2009 && substr(build, 4) < 1021)
      )
    )
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + v +
      '\n  Fixed version     : 1.9.6 / 1.8.10' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, v);
