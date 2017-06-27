#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81488);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2015-1349");
  script_bugtraq_id(72673);
  script_osvdb_id(118546);

  script_name(english:"ISC BIND 9.9.6-S2 DNSSEC Validation DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND (via DNSco) is potentially affected by a denial of service
vulnerability due to an error relating to DNSSEC validation and the
managed-keys feature. A remote attacker can trigger an incorrect
trust-anchor management scenario in which no key is ready for use,
resulting in an assertion failure and daemon crash.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.dns-co.com/solutions/");
  # https://kb.isc.org/article/AA-00913/0/BIND-9-Security-Vulnerability-Matrix.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56e964d9");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01235/0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.6-S3 or later.

Alternatively, as a workaround, do not use 'auto' for the
dnssec-validation or dnssec-lookaside options and do not configure a
managed-keys statement.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:dnsco_bind");
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

# Vuln 9.9.6-S2
if (ver == "9.9.6-S2")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 9.9.6-S3' +
      '\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
