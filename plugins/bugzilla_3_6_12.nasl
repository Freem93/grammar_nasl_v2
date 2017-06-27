#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62973);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id(
    "CVE-2012-4189",
    "CVE-2012-4197",
    "CVE-2012-4198",
    "CVE-2012-4199",
    "CVE-2012-5883"
  );
  script_bugtraq_id(56385, 56504);
  script_osvdb_id(87239, 87295, 87296, 87303, 87304);

  script_name(english:"Bugzilla < 3.6.12 / 4.0.9 / 4.2.4 / 4.4rc1 Multiple Vulnerabilities");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is affected by multiple vulnerabilities :

  - Due to incorrectly filtered field values in tabular
    reports, code can be injected, which could allow
    cross-site scripting (XSS).  Note that this affects
    versions 4.1.1 to 4.2.3 and 4.3.1 to 4.3.3.
    (CVE-2012-4189)

  - When trying to mark an attachment in a restricted bug as
    obsolete, the description is disclosed in the resulting
    error message.  Note that this affects versions 2.16 to
    3.6.11, 3.7.1 to 4.0.8, 4.1.1 to 4.2.3, and 4.3.1 to
    4.3.3. (CVE-2012-4197)

  - When calling the User.get method with a 'groups'
    argument, the existence of the groups is leaked, which
    could allow an attacker to identify groups via an error
    message.  Note that this affects versions 3.7.1 to
    4.0.8,
    4.1.1 to 4.2.3, and 4.3.1 to 4.3.3. (CVE-2012-4198)

  - Custom field names are disclosed in the JavaScript
    code generated when the visibility of a custom field is
    controlled by a restricted product or component of a
    product.  Note that this affects versions 3.3.4 to
    3.6.11, 3.7.1 to 4.0.8, 4.1.1 to 4.2.3, and 4.3.1
    to 4.3.3. (CVE-2012-4199)

  - A vulnerability exists in swfstore.swf from YUI2 that
    could allow JavaScript injection exploits to be created
    against domains hosting the affected YUI .swf file. 
    Note
    that this affects versions 3.7.1 to 4.0.8, 4.1.1 to
    4.2.3, and 4.3.1 to 4.3.3. (CVE-2012-5883)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.6.11/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 3.6.12 / 4.0.9 / 4.2.4 / 4.4rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 3.6.12 / 4.0.9 / 4.2.4 / 4.4rc1 are vulnerable
# Specific ranges were provided by bugzilla.org/security/3.6.11/
if (
  # 2.16 to 3.6.11
  (ver[0] == 2 && ver[1] > 15) ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 12) ||

  # 3.7.1 to 4.0.8
  (ver[0] == 3 && ver[1] == 7 && ver[2] > 0) ||
  (ver[0] == 3 && ver[1] > 7) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 9) ||

  # 4.1.1 to 4.2.3
  (ver[0] == 4 && ver[1] == 1 && ver[2] > 0) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 4) ||

  # 4.3.1 to 4.3.3
  (ver[0] == 4 && ver[1] == 3 && ver[2] > 0 && ver[2] <= 3)
)

{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.6.12 / 4.0.9 / 4.2.4 / 4.4rc1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
