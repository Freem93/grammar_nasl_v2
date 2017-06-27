#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72815);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/21 19:27:16 $");

  script_cve_id("CVE-2013-4508", "CVE-2013-4559", "CVE-2013-4560");
  script_bugtraq_id(63534, 63686, 63688);
  script_osvdb_id(99365, 99759, 99760);

  script_name(english:"lighttpd < 1.4.34 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.34. It is, therefore, affected by the following
vulnerabilities :

  - When Server Name Indication (SNI) is enabled, a flaw
    exists that could cause the application to use all
    available SSL ciphers, including weak ciphers. Remote
    attackers could potentially hijack sessions or obtain
    sensitive information by sniffing the network.
    Note only versions 1.4.24 to 1.4.33 are affected.
    (CVE-2013-4508)

  - A flaw exists in the clang static analyzer because it
    fails to perform checks around setuid (1), setgid (2),
    and setgroups (3) calls. This could allow a remote
    attacker to gain elevated privileges. (CVE-2013-4559)

  - A use-after-free error exists in the clang static
    analyzer, when the FAM stat cache engine is enabled.
    This could allow remote attackers to dereference
    already freed memory and crash the program.
    (CVE-2013-4560)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.lighttpd.net/2014/1/20/1-4-34/");
  script_set_attribute(attribute:"see_also", value:"http://redmine.lighttpd.net/issues/2525");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2013_01.txt");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2013_02.txt");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2013_03.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.34 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

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
  version =~ "^1\.4\.([0-9]|[1-2][0-9]|3[0-3])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.34\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "lighttpd", port, version);
