#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73760);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/30 23:35:28 $");

  script_cve_id("CVE-2014-2210");
  script_bugtraq_id(66644);
  script_osvdb_id(105359, 106134, 106135, 106136, 106137);

  script_name(english:"CA ERwin Web Portal 9.5 Multiple Directory Traversals");
  script_summary(english:"Gets version and build date of CA ERwin Web Portal");

  script_set_attribute(attribute:"synopsis", value:
"A web portal with multiple directory traversal vulnerabilities is
running on the remote host.");
  script_set_attribute(attribute:"description", value:
"CA ERwin Web Portal version 9.5 with a build date before March 20,
2014 was detected on the remote host. This version contains multiple
directory traversal vulnerabilities that an attacker could use to
access sensitive information, or possibly execute arbitrary code.");
  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={7F968A14-7407-4BCF-9EB1-EFE9F0E6D663}
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f14d28a");
  # http://blogs.ca.com/securityresponse/2014/04/03/ca20140403-01-security-notice-for-ca-erwin-web-portal/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3652210");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-093/");
  script_set_attribute(attribute:"solution", value:
"Update to CA ERwin Web Portal 9.5 build 2014-03-20
(MIMM-win32-721-20140320.exe) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:erwin_web_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 19980);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

product = "CA ERwin Web Portal";
vuln_ver = "9.5";
patched_year = "2014";
patched_month = "03";
patched_day = "20";

port = get_http_port(default:19980);

url = '/MM/';

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if ("Meta Integration" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_INST, product, port);

url = "/MM/SessionChecker.do?JsLoaded=true";

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if ("oem_loginheaderTitle" >!< res[2]) audit(AUDIT_WEB_APP_NOT_INST, product, port);

match = eregmatch(string:res[2], pattern:"CA ERwin Web Portal r([0-9.]+) Login");
if (isnull(match)) audit(AUDIT_WEB_APP_NOT_INST, product, port);

ver = match[1];
if (ver != vuln_ver) audit(AUDIT_INST_VER_NOT_VULN, product, ver);

url = "/MM/js/BuildInfo-gen.js";

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if ("BUILD_DATE" >!< res[2])
  audit(AUDIT_UNKNOWN_WEB_APP_VER, product, port);

match = eregmatch(string:res[2], pattern:'BUILD_DATE +: \"([0-9]{4})-([0-9]{2})-([0-9]{2}) ');

if (isnull(match) || isnull(match[1]) || isnull(match[2]) || isnull(match[3]))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, product, port);

build_year = match[1];
build_month = match[2];
build_day = match[3];

build_date = build_year + "." + build_month + "." + build_day;
patched_date = patched_year + "." + patched_month + "." + patched_day;

if (ver_compare(ver:build_date, fix:patched_date, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Detected version : ' + ver + ' build ' + build_date +
      '\n  Patched version  : ' + vuln_ver + ' build ' + patched_date +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, product, ver + " build " + build_date);
