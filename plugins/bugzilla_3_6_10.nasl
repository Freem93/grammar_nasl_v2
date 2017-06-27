#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61650);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2012-1968", "CVE-2012-1969");
  script_bugtraq_id(54708);
  script_osvdb_id(84244, 84245);

  script_name(english:"Bugzilla < 3.6.10 / 4.0.7 / 4.2.2 / 4.3.2 Multiple Information Disclosures");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is affected by multiple information disclosure
vulnerabilities :

  - In HTML bugmails, all bug IDs and attachment IDs are
    linkified, and hovering these links displays a tooltip
    with the bug summary or the attachment description if
    the user is allowed to see the bug or attachment.  But
    when validating user permissions when generating the
    email, the permissions of the user who edited the bug
    were taken into account instead of the permissions of
    the addressee. This means that confidential information
    could be disclosed to the addressee if the other user
    has more privileges than the addressee. (CVE-2012-1968)

  - The description of a private attachment could be
    visible to a user without permissions to access the
    attachment if the attachment ID is mentioned in a
    public comment that the user can see. (CVE-2012-1969)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # nb: the title's wonky ("4.3.1, 4.2.1, 4.0.6, and 3.6.9 Security
  #     Advisory") in their advisory posting, but the text seems fine.
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.6.9/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jul/153");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 3.6.10 / 4.0.7 / 4.2.2 / 4.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

# Versions less than 3.6.10 / 4.0.7 / 4.2.2 / 4.3.2 are vulnerable
# Specific ranges were provided by bugzilla.org/security/3.6.9/
if (
  #2.17.5 to 3.6.9
  (ver[0] == 2 && ver[1] == 17 && ver[2] > 4) ||
  (ver[0] == 2 && ver[1] > 17) ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 10) ||

 # 3.7.1 to 4.0.6
  (ver[0] == 3 && ver[1] == 7 && ver[2] > 0) ||
  (ver[0] == 3 && ver[1] > 7) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 7) ||

 # 4.1.1 to 4.2.1
  (ver[0] == 4 && ver[1] == 1 && ver[2] > 0) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 2) ||
  version == '4.3.1'
)

{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.6.10 / 4.0.7 / 4.2.2 / 4.3.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
