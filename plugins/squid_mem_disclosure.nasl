#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15929);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2004-2479");
  script_bugtraq_id(11865);
  script_osvdb_id(12282);

  script_name(english:"Squid < 2.5.STABLE8 Malformed Host Name Error Message Information Disclosure");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:'synopsis', value:
"The remote proxy server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:'description', value:
"According to its banner, the version of Squid running on the remote
host is prior to 2.5.STABLE8. It is, therefore, affected by an
information disclosure vulnerability due to improper handling of
malformed host names. An unauthenticated, remote attacker can exploit
this issue to disclose the contents of recently freed memory as error
messages.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:'see_also', value:'http://bugs.squid-cache.org/show_bug.cgi?id=1143');
  script_set_attribute(attribute:'solution', value:
"Upgrade to Squid version 2.5.STABLE8 or later. Alternatively, apply
the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Squid";

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (empty_or_null(list)) audit(AUDIT_NOT_INST, app);

# banner checks of open source software are prone to false-
# positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

item = branch(keys(list));

port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
version = list[item];

if (version =~ "^2\.5([^0-9.]|$)")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

fix = '2.5.STABLE8';

if (
    version =~ "^[01]\." ||
    version =~ "^2\.[0-4]([^0-9]|$)" ||
    version =~ "^2\.5\.PRE([0-9]|$)" ||
    version =~ "^2\.5\.RC1([^0-9]|$)" ||
    version =~ "^2\.5\.[A-Za-z]*[0-7]([^0-9]|$)"
) 
{
  report = NULL;

  source = get_kb_item('http_proxy/'+port+'/squid/source');
  if (!empty_or_null(source))
    report =
      '\n  Version source    : ' + source;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fix               : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
 audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
