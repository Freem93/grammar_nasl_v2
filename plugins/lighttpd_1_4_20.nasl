#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34332);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2008-1531", "CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
  script_bugtraq_id(28489, 31434, 31599, 31600);
  script_osvdb_id(43788, 48682, 48886, 48889);

  script_name(english:"lighttpd < 1.4.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.20. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the
    connection_state_machine() function that is triggered
    when disconnecting before a download has finished. An
    unauthenticated, remote attacker can exploit this to
    cause all active SSL connections to be lost.
    (CVE-2008-1531)

  - A memory leak flaw exists in the http_request_parse()
    function. An unauthenticated, remote attacker can
    exploit this, via a large number of requests with
    duplicate request headers, to cause a denial of service
    condition. (CVE-2008-4298)

  - A security bypass vulnerability exists due to comparing
    URIs to patterns in url.redirect and url.rewrite
    configuration settings before performing URL decoding.
    An unauthenticated, remote attacker can exploit this to
    bypass intended access restrictions, resulting in the
    disclosure or modification of sensitive data.
    (CVE-2008-4359)

  - A security bypass vulnerability exists in mod_userdir
    due to performing case-sensitive comparisons even on
    case-insensitive operating systems and file systems. An
    unauthenticated, remote attacker can exploit this to
    bypass intended access restrictions, resulting in the
    disclosure of sensitive information. (CVE-2008-4360)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://redmine.lighttpd.net/issues/285");
  script_set_attribute(attribute:"see_also", value:"https://redmine.lighttpd.net/issues/1589");
  script_set_attribute(attribute:"see_also", value:"https://redmine.lighttpd.net/issues/1589");
  script_set_attribute(attribute:"see_also", value:"https://redmine.lighttpd.net/issues/1774");
  # http://web.archive.org/web/20120118054919/http://www.lighttpd.net/2008/9/30/1-4-20-otherwise-the-terrorists-win
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d6f179d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# No backport for lighttpd
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!get_kb_item("www/lighttpd")) exit(0);

port = get_http_port(default:80);

banner = get_http_banner(port: port);

srv = egrep(string: banner, icase: 1, pattern: '^Server:[ \t]*lighttpd');
if (! srv) exit(0);

srv = chomp(srv);
if (srv =~ "lighttpd/1\.([0-3]\.|4\.([0-9]|[01][0-9])([^0-9]|$))")
{
  if (report_verbosity)
  {
    ver = strstr(srv, "lighttpd/") - "lighttpd/";
    report = strcat(
      '\n',
      'lighttpd version ', ver, ' appears to be running on the remote host\n',
      'based on the following Server response header :\n',
      '\n',
      '  ', srv, '\n'
    );
    security_hole(port: port, extra: report);
  }
  else
    security_hole(port);
}
