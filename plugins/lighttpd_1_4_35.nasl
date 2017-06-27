#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73123);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/21 19:27:16 $");

  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_bugtraq_id(66153, 66157);
  script_osvdb_id(104381, 104382);

  script_name(english:"lighttpd < 1.4.35 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.35. It is, therefore, affected by the following
vulnerabilities :

  - A SQL injection flaw exists in the 'mod_mysql_vhost'
    module where user input passed using the hostname is not
    properly sanitized. A remote attacker can exploit this
    to inject or manipulate SQL queries, resulting in the
    manipulation or disclosure of data. (CVE-2014-2323)

  - A traverse outside of restricted path flaw exists with
    the 'mod_evhost' and 'mod_simple_vhost' modules where
    user input passed using the hostname is not properly
    sanitized. A remote attacker can exploit this to gain
    access to potentially sensitive data. (CVE-2014-2324)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.lighttpd.net/2014/3/12/1.4.35/");
  # http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/2959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92dd0985");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");
  # http://download.lighttpd.net/lighttpd/security/lighttpd-1.4.34_fix_mysql_injection.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c57451b6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.35. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

server_header = http_server_header(port:port);
if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ("lighttpd" >!< tolower(server_header))  audit(AUDIT_WRONG_WEB_SERVER, port, "lighttpd");

matches = eregmatch(string:server_header, pattern:"^lighttpd\/([a-zA-Z0-9.-_]+)");
if (!matches) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "lighttpd", port);
version = matches[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^0\." ||
  version =~ "^1\.[0-3]\." ||
  version =~ "^1\.4\.([0-9]|[1-2][0-9]|3[0-4])($|[^0-9])")
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.35\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "lighttpd", port, version);
