#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79861);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/18 20:53:33 $");

  script_cve_id("CVE-2014-8500", "CVE-2014-8680");
  script_bugtraq_id(71590, 73191);
  script_osvdb_id(115524, 115596);

  script_name(english:"ISC BIND 9 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by multiple denial of service vulnerabilities :

  - A flaw exists within the Domain Name Service due to an
    error in the code used to follow delegations. A remote
    attacker, with a maliciously-constructed zone or query,
    could potentially cause the service to issue unlimited
    queries leading to resource exhaustion. (CVE-2014-8500)

  - Multiple flaws exist with the GeoIP feature. These flaws
    could allow a remote attacker to cause a denial of
    service. Note these issues only affect the 9.10.x
    branch. (CVE-2014-8680)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01216/");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01217/");
  # https://lists.isc.org/pipermail/bind-announce/2014-December/000932.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92718697");
  # https://lists.isc.org/pipermail/bind-announce/2014-December/000933.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f54d158");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND version 9.9.6-P1 / 9.10.1-P1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check whether BIND is vulnerable, and recommend an upgrade.
fix = NULL;

# Vuln BIND 9.0.x -> 9.8.x, 9.9.0 -> 9.9.6, 9.10.0 -> 9.10.1
if (
  ver =~ "^9\.[0-8]\." ||
  ver =~ "^9\.9\.[0-5]([^0-9]|$)" ||
  ver =~ "^9\.9\.6($|([ab][12]|rc[12])$)"
) fix = '9.9.6-P1';
else if (
  ver =~ "^9\.10\.0([^0-9]|$)" ||
  ver =~ "^9\.10\.1($|([ab][12]|rc[12])$)"
) fix = '9.10.1-P1';
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
}
else security_hole(port:53, proto:"udp");
