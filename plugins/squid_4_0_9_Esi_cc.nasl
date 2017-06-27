#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91193);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/18 15:32:40 $");

  script_cve_id(
    "CVE-2016-4052",
    "CVE-2016-4053",
    "CVE-2016-4054"
  );
  script_osvdb_id(
    137402,
    137403,
    137404
  );

  script_name(english:"Squid 3.x < 3.5.17 / 4.x < 4.0.9 Esi.cc Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.x prior to 3.5.17 or 4.x prior to 4.0.9. It is, therefore,
affected by multiple vulnerabilities :

  - An assertion fault exists in file esi/Esi.cc that is
    triggered when handling ESI responses. An
    unauthenticated, remote attacker can exploit this, via
    an HTTP server that uses specially crafted Edge Side
    Includes (ESI), to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-4052)

  - A flaw exists in file esi/Esi.cc due to improper
    validation of user-supplied input when handling ESI
    responses. An unauthenticated, remote attacker can
    exploit this, via specially crafted ESI responses, to
    disclose sensitive stack layout information.
    (CVE-2016-4053)

  - A buffer overflow condition exists in file esi/Esi.cc
    due to improper validation of user-supplied input when
    handling ESI responses. An unauthenticated, remote
    attacker can exploit this, via specially crafted ESI
    responses, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-4054)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.
Furthermore, the patch released to address these issues does not
update the version given in the banner. If the patch has been applied
properly, and the service has been restarted, then consider this to be
a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2016_6.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.5.17 / 4.0.9 or later. Alternatively, apply
the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");

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

if (version =~ "^3.\[01]\.")
  fix = "Upgrade to a fixed version (see solution).";
else if (
  version =~ "^3\.[2-4]\." ||
  version =~ "^3\.5\.([0-9]|1[0-6])([^0-9]|$)"
)
  fix = "Apply vendor-supplied patch or upgrade to fixed version (see solution).";
else if (version =~ "^4\.0\.[0-8]([^0-9]|$)")
  fix = "Upgrade to version 4.0.9";
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);

if (!empty_or_null(fix))
{
  source = get_kb_item('http_proxy/'+port+'/squid/source');
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  fix               : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
