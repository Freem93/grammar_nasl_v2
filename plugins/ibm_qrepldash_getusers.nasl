#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65894);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2013-0584");
  script_osvdb_id(92643);
  script_xref(name:"TRA", value:"TRA-2013-09");

  script_name(english:"IBM InfoSphere Data Replication Dashboard User Enumeration");
  script_summary(english:"Gets a list of users");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to enumerate the list of users for a web application
hosted on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM InfoSphere Data Replication Dashboard hosted on the
remote web server displays its list of users without requiring
authentication.  A remote, unauthenticated attacker could use this
information to mount further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21634798");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-09");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM InfoSphere Data Replication Dashboard version
10.2.0.0-b113 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_replication_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_qrepldash_detect.nasl");
  script_require_keys("www/ibm_infosphere_data_replication_dashboard");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'ibm_infosphere_data_replication_dashboard', port:port, exit_on_fail:TRUE);

url = install['dir'] + '/getUsers.do';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

match = eregmatch(string:res[2], pattern:'<Result uls="([^"]+)"');
if (isnull(match))
  exit(0, 'Unable to get user list on port ' + port + '.');

if (report_verbosity > 0)
{
  trailer = 'Which returned the following list of users :\n';
  users = split(match[1], sep:';', keep:FALSE);
  foreach user (sort(users))
    trailer += '\n  ' + user;
  report = get_vuln_report(items:url, port:port, trailer:trailer);
  security_warning(port:port, extra:report);
}
else security_warning(port);

