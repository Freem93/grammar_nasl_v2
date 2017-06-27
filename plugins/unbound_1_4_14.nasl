#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57574);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/12 15:53:16 $");

  script_cve_id("CVE-2011-4528", "CVE-2011-4869");
  script_bugtraq_id(51115);
  script_osvdb_id(77909, 77910);
  script_xref(name:"CERT", value:"209659");

  script_name(english:"Unbound < 1.4.14 / 1.4.13p2 Multiple DoS");
  script_summary(english:"Checks the version of Unbound.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Unbound DNS
resolver is affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists due to an
    attempt to free unallocated memory during the processing
    of duplicate CNAME records in a signed zone. An attacker
    can exploit this, via a specially crafted response, to
    cause a daemon crash, resulting in a denial of service
    condition. (CVE-2011-4528)

  - A denial of service vulnerability exists due to improper
    proof processing for NSEC3-signed zones. An attacker can
    exploit this, via a malformed response that lacks
    expected NSEC3 records, to cause a daemon crash,
    resulting in a denial of service condition.
    (CVE-2011-4869)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.unbound.net/downloads/CVE-2011-4528.txt");
  # http://www.unbound.net/pipermail/unbound-users/2011-December/002153.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fa3cd4a");
  script_set_attribute(attribute:"solution", value:"Upgrade to Unbound version 1.4.14 / 1.4.13p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unbound:unbound");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("unbound_version.nasl");
  script_require_keys("unbound/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("unbound/version");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_version = "1.4.14 / 1.4.13p2";
port = 53;

tcp = get_kb_item("DNS/tcp/53");
if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

# if version < 1.4.14 / 1.4.13p2
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-3]($|[^0-9])" ||
  version =~ "^1\.4($|\.[0-9]($|[^0-9.])|\.1[0-2]($|[^0-9.])|\.13($|p[01]($|[^0-9.]))|\.14rc)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, proto:proto, extra:report);
  }
  else security_warning(port:port, proto:proto);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Unbound', port, version);
