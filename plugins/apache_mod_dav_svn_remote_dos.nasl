#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80864);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/04 20:57:14 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108");
  script_bugtraq_id(71725, 71726);
  script_osvdb_id(115921, 115922);

  script_name(english:"Apache Subversion 1.7.x < 1.7.19 / 1.8.x < 1.8.11 Multiple Remote DoS");
  script_summary(english:"Checks target for vulnerable mod_dav svn.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache SVN 1.7.x prior to
1.7.19 or 1.8.x prior to 1.8.11. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - A NULL pointer dereference flaw exists in 'mod_dav_svn'
    that is triggered when handling REPORT requests. A
    remote attacker, using a specially crafted request, can
    cause the listener process to crash. (CVE-2014-3580)

  - A NULL pointer dereference flaw exists in 'mod_dav_svn'
    that is triggered when handling requests for
    non-existent virtual transaction names. A remote
    attacker, using a specially crafted request, can cause
    the listener process to crash. (CVE-2014-8108)");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2014-3580-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2014-8108-advisory.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Subversion 1.7.19 / 1.8.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Apache mod_dav_svn";

port = get_http_port(default:80);

# some SVN installations have versioning in the
# server-response of the HTTP header

server_name = http_server_header(port:port);

if(isnull(server_name))
  audit(AUDIT_WEB_NO_SERVER_HEADER, port);

# check to see if host is running the apache web server
if ('Apache' >!< server_name) audit(AUDIT_NOT_LISTEN, app_name, port);

source = NULL;
version = UNKNOWN_VER;

fix = "";

# The raw strings below are needed for
# installations where SVN is not included in the
# HTTP server-response field

svn = 'SVN/';
subversion = 'Subversion';
visualsvn = '<svn version=';

pattern = "SVN/([0-9]\.[0-9]\.[0-9][0-9])";
item = eregmatch(pattern:pattern, string:server_name);

source = server_name;
version = item[1];

# For subversion installations where SVN
# is not found in the server-response
if (svn >!< server_name)
{
  # if SVN isn't found in the server-response of the HTTP header we use a brute method
  # most subversion installations use /svn by default including VisualSVN for Windows
  # and Apache Subversion docs use /svn as well.

  uri = make_list( '/subversion', '/repository', '/svnrepo', '/repo', '/svn/', '/!/#', '/' );
  lnk = "";

  for (i = 0; i < max_index(uri); i++ )
  {
    # brute force approach: is mod dav svn enabled on apache server
    resp = http_send_recv3(method: 'GET', item:uri[i], port:port);

    # we land here if server-response yields nothing but subversion
    # is detected in the footer of the html body in the HTTP response
    if ((svn) >< resp[1]+resp[2] || (subversion) >< resp[1]+resp[2])
    {
      pattern = "Subversion<\/a> version ([0-9]\.[0-9]\.[0-9]+[0-9])";
      item = eregmatch(pattern:pattern, string:resp[2]);
      version = item[2];
      lnk = uri[i];
    }

    # we land here if the server-response yields nothing but visualsvn
    # is found in the body of the HTTP response.
    if ((visualsvn) >< resp[1]+resp[2])
    {
      pattern = '<svn version=\"([0-9]\\.[0-9]\\.[0-9]+[0-9])';
      item = eregmatch(pattern:pattern, string:resp[2]);
      version = item[1];
      lnk = uri[i];
    }
  }
}

if (version =~ "^1\.7\." && ver_compare(ver:version, fix:"1.7.19", strict:FALSE) == -1)
  fix = "1.7.19";

if (version =~ "^1\.8\." && ver_compare(ver:version, fix:"1.8.11", strict:FALSE) == -1)
  fix = "1.8.11";

if (fix != "")
{
  url = build_url(port:port, qs:url+lnk);
  source += ' with mod_dav_svn enabled';
  if (report_verbosity > 0)
  {
    report =
      '\n Version source    : ' + source +
      '\n Installed version : ' + version +
      '\n Fixed version     : ' + fix +
      '\n Request URL       : ' + url +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port);
