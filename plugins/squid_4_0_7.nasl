#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89080);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id(
    "CVE-2016-2569",
    "CVE-2016-2570",
    "CVE-2016-2571",
    "CVE-2016-2572"
  );
  script_osvdb_id(
    134900,
    134901
  );

  script_name(english:"Squid 3.x < 3.5.15 / 4.x < 4.0.7 Multiple DoS");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is potentially affected by multiple denial of
service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.x prior to 3.5.15 or 4.x prior to 4.0.7. It is, therefore,
potentially affected by multiple denial of service vulnerabilities :

  - A flaw exists due to not properly appending data to
    String objects. A remote attacker can exploit this, via
    a crafted HTTP Vary header, to cause an assertion
    failure and daemon exit, resulting in a denial of
    service. (CVE-2016-2569)

  - A flaw exists in the Edge Side Includes (ESI) parser due
    to a failure to check buffer limits during XML parsing.
    A remote attacker can exploit this, via a crafted XML
    document, to cause an assertion failure and daemon exit,
    resulting in a denial of service. (CVE-2016-2570)

  - A flaw exists in http.cc that allows the storage of
    certain data even after a response-parsing failure. A
    remote attacker can exploit this, via a malformed
    server response, to cause an assertion failure and
    daemon exit, resulting in a denial of service.
    CVE-2016-2571)

  - A flaw exists in http.cc due to reliance on the HTTP
    status code even after a response-parsing failure. A
    remote attacker can exploit this, via a malformed
    server response, to cause an assertion failure and
    daemon exit, resulting in a denial of service.
    (CVE-2016-2572)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.
Furthermore, the patch released to address these issues does not
update the version given in the banner. If the patch has been applied
properly, and the service has been restarted, then consider this to be
a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2016_2.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.5.15 / 4.0.7 or later. Alternatively, apply
the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app="Squid";

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (empty_or_null(list)) audit(AUDIT_NOT_INST, app);

# banner checks of open source software are prone to false-
# positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

item = branch(keys(list));

port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
version = list[item];

if(
  version =~ "^3\.5([^0-9.]|$)" ||
  version =~ "^4\.0([^0-9.]|$)"
) audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

fix = '';

if (
  version =~ "^3\.[0-4]\." ||
  version =~ "^3\.5\.([0-9]|1[0-4])([^0-9]|$)"
)
  fix = '3.5.15';
else if (version =~ "^4\.0\.[0-6]([^0-9]|$)")
  fix = '4.0.7';
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);

if (!empty_or_null(fix))
{
  source = get_kb_item('http_proxy/'+port+'/squid/source');
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed versions    : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
