#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(85513);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/19 14:23:08 $");

  script_cve_id("CVE-2014-8111");
  script_bugtraq_id(74265);
  script_osvdb_id(120601);

  script_name(english:"Apache Tomcat JK Connector 1.2.x < 1.2.41 JkUnmount Directive Handling Remote Information Disclosure");
  script_summary(english:"Checks for version of mod_jk.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description",  value:
"Based on the Server response header, the installation of the JK
Connector (mod_jk) in Apache Tomcat listening on the remote host is
version 1.2.x prior to 1.2.41. It is, therefore, affected by an
information disclosure vulnerability due to improper handling of the
'JkUnmount' directive and multiple, adjacent slashes in requests. A
remote attacker can exploit this to access restricted private
artifacts, resulting in the disclosure of sensitive information.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://tomcat.apache.org/connectors-doc/news/20150101.html#JK-1.2.41 released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a336ab81");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=revision&revision=1647017");
  script_set_attribute(attribute:"solution", value:"Upgrade to mod_jk version 1.2.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2014/12/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2014/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat_connectors");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl", "find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app_name = 'mod_jk';

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (empty_or_null(banner)) audit(AUDIT_WEB_BANNER_NOT, port);

if ("Server: " >!< banner) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ("mod_jk"   >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "one with mod_jk");

foreach line (split(banner, keep:FALSE))
{
  if ("Server: " >!< line) continue;
  serv = line - 'Server: ';
  break;
}

# audit() if somehow header was 'Server: ' only
if (strlen(serv) == 0) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

# Paranoid scans only
if (report_paranoia < 2) audit(AUDIT_PARANOID);

matches = eregmatch(pattern: 'mod_jk/([0-9.]+[A-Za-z0-9.-]*)', string: serv);
if (!matches) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

version = tolower(matches[1]);

# Not granular enough
if (version =~ "^1(\.2)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

# Not 1.2.x
if (version !~ "^1\.2($|[^0-9])") audit(AUDIT_NOT_INST, app_name + " 1.2.x");

if (
  version =~ "^1\.2\.[0-9]($|[^0-9])"      ||
  version =~ "^1\.2\.[0-3][0-9]($|[^0-9])" ||
  version =~ "^1\.2\.40($|[^0-9])"         ||
  version =~ "^1\.2\.41-(beta|dev)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n    Server response header : ' + serv  +
      '\n    Installed version      : ' + version +
      '\n    Fixed version          : 1.2.41\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
