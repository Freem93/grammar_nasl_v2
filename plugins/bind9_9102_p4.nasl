#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85896);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/19 18:41:38 $");

  script_cve_id("CVE-2015-5722", "CVE-2015-5986");
  script_osvdb_id(126995, 126997);

  script_name(english:"ISC BIND 9.0.x < 9.9.7-P3 / 9.10.x < 9.10.2-P4 Multiple DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND running on the remote name server is potentially affected by
the following vulnerabilities :

  - A denial of service vulnerability exists due to an
    assertion flaw that is triggered when parsing malformed
    DNSSEC keys. An unauthenticated, remote attacker can
    exploit this, via a specially crafted query to a zone
    containing such a key, to cause a validating resolver to
    exit. (CVE-2015-5722)

  - A denial of service vulnerability exists in the
    fromwire_openpgpkey() function in openpgpkey_61.c that
    is triggered when the length of data is less than 1. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted response to a query, to cause an
    assertion failure that terminates named. (CVE-2015-5986)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01287");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01291");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.7-P3 / 9.10.2-P4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied

fix = '';

# 9.0.0 through BIND 9.9.7-P2 and BIND 9.10.2-P3 are vulnerable
if (
  ver =~ "^9\.[0-8]([^0-9]|$)" ||
  ver =~ "^9\.9\.[0-6]([^0-9]|$)" ||
  ver =~ "^9\.9\.7($|([ab][12]|rc[12]|-P[12])$)"
) fix = '9.9.7-P3';

if (
  ver =~ "^9\.10\.[01]([^0-9]|$)" ||
  ver =~ "^9\.10\.2($|([ab][12]|rc[12]|-P[1-3])$)"
) fix = '9.10.2-P4';

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
