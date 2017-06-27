#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84728);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/13 04:38:20 $");

  script_cve_id("CVE-2015-4620");
  script_bugtraq_id(75588);
  script_osvdb_id(124233);

  script_name(english:"ISC BIND 9.7.x < 9.9.7-P1 / 9.10.x < 9.10.2-P2 Resolver DNSSEC Validation DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is potentially affected by a denial of service vulnerability,
when configured as a recursive resolver with DNSSEC validation, due to
an error that occurs during the validation of specially crafted zone
data returned in an answer to a recursive query. A remote attacker can
exploit this, by causing a query to be performed against a maliciously
constructed zone, to crash the resolver.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01267");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01270");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01269");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.7-P1 / 9.10.2-P2 or later.

Alternatively, as a workaround, disable DNSSEC validation by setting
the 'dnssec-validation' option to no.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '';

# Vuln 9.7.x < 9.9.7-P1 / 9.10.x < 9.10.2-P2
if (
  ver =~ "^9\.[7-8]([^0-9]|$)" ||
  ver =~ "^9\.9\.[0-6]([^0-9]|$)" ||
  ver =~ "^9\.9\.7($|([ab][12]|rc[12])$)"
) fix = '9.9.7-P1';

if (
  ver =~ "^9\.10\.[01]([^0-9]|$)" ||
  ver =~ "^9\.10\.2($|([ab][12]|rc[12]|-P1)$)"
) fix = '9.10.2-P2';

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:53, proto:"udp", extra:report);
  }
  else security_hole(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
