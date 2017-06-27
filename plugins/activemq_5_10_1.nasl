#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81374);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id(
    "CVE-2014-3576",
    "CVE-2014-3600",
    "CVE-2014-3612",
    "CVE-2014-8110"
  );
  script_bugtraq_id(
    72510,
    72511,
    72513
  );
  script_osvdb_id(
    63367,
    118027,
    118028,
    118030,
    118040,
    118041,
    125118
  );

  script_name(english:"Apache ActiveMQ 5.x < 5.10.1 / 5.11.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ActiveMQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is 5.x prior
to 5.10.1 / 5.11.0. It is, therefore, potentially affected by multiple
vulnerabilities :

  - An unauthenticated, remote attacker can crash the broker
    listener by sending a packet to the same port that a
    message consumer or product connects to, resulting in a
    denial of service condition. (CVE-2014-3576)

  - An XML external entity (XXE) injection vulnerability 
    exists that is related to XPath selectors. A remote
    attacker can exploit this, via specially crafted XML
    data, to disclose the contents of arbitrary files.
    (CVE-2014-3600)

  - A flaw exists in the LDAPLoginModule of the Java
    Authentication and Authorization Service (JAAS) which
    can be triggered by the use of wildcard operators
    instead of a username or by invalid passwords. A remote
    attacker can exploit this to bypass authentication.
    (CVE-2014-3612)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the web administrative console. (CVE-2014-8110)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-3600-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8309341");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-3612-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3d4e09f");
  # http://activemq.apache.org/security-advisories.data/CVE-2014-8110-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b2b5313");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.10.1 / 5.11.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
fix = '5.10.1';
report_fix = fix + " / 5.11.0";

if (
  (version =~ "^5\.") &&
  (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
)
{
  set_kb_item(name:"www/" + port + "/XSS", value:TRUE);
    if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
