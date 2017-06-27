#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81487);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2014-8500", "CVE-2014-8680", "CVE-2015-1349");
  script_bugtraq_id(71590, 72673, 73191);
  script_osvdb_id(115524, 115596, 118546);

  script_name(english:"ISC BIND 9.10.2 < 9.10.2rc2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is potentially affected by multiple vulnerabilities :

  - A flaw exists within the Domain Name Service due to an
    error in the code used to follow delegations. A remote
    attacker, with a maliciously-constructed zone or query,
    can cause the service to issue unlimited queries,
    resulting in resource exhaustion. (CVE-2014-8500)

  - Multiple flaws exist with GeoIP functionality. These
    flaws allow a remote attacker to cause a denial of
    service. Note that these issues only affect the 9.10.x
    branch. (CVE-2014-8680)

  - A denial of service vulnerability exists due to an error
    relating to DNSSEC validation and the managed-keys
    feature. A remote attacker can trigger an incorrect
    trust-anchor management scenario in which no key is
    ready for use, resulting in an assertion failure and
    daemon crash. (CVE-2015-1349)

  - An error exists related to handling the
    'geoip-directory' option in named.conf when running
    'rndc reconfig' or 'rndc reload' that allows connections
    by unintended clients.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01235/0");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01246/0/BIND-9.10.2rc2-Release-Notes.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND version 9.10.2rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

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

# Vuln BIND 9.10.2.x < 9.10.2rc2
# Only b1, rc1 and rc2 exist.
if (ver =~ "^9\.10\.2(b1|rc1)$")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.10.2rc2' +
      '\n';
    security_hole(port:53, proto:"udp", extra:report);
  }
  else security_hole(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
