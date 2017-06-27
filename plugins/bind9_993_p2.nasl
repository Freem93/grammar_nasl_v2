#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69106);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/24 02:02:49 $");

  script_cve_id("CVE-2013-4854");
  script_bugtraq_id(61479);
  script_osvdb_id(95707);

  script_name(english:"ISC BIND 9 RDATA Section Handling DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND can be forced to crash via specially crafted queries containing
malformed 'rdata' contents.

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually affected.

Further note that this vulnerability is being actively exploited at the
time of this writing.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-210/");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01015");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01016/");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.5-P2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.3-P2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://www.dns-co.com/solutions/bind/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.3-S1-P1 / 9.9.3-P2 / 9.8.5-P2 or later, or
apply the vendor-supplied patch.

In the case of development branches, such as 9.8.6rc1 / 9.9.4rc1 /
9.9.4-S1rc1, no patch is currently available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
# Vuln BIND 9.7.0-9.7.7, 9.8.0-9.8.5-P1, 9.9.0-9.9.3-P1, 9.8.6b1 and 9.9.4b1
fix = NULL;

if (ver =~ "^9\.7($|[^0-9])")
  # Vuln 9.7.0-9.7.7 (there is no 9.7.x fix; recommend higher upgrade)
  fix = '9.8.5-P2';
else if (
  # Vuln 9.8.0-9.8.5-P1
  ver =~ "^9\.8\.[0-4]($|[^0-9])" ||
  ver =~ "^9\.8\.5(-P1|b[1-2]|rc[1-2])?$"
)
  fix = '9.8.5-P2';
else if (
  # Vuln 9.9.0-9.9.3-P1
  ver =~ "^9\.9\.[0-2]($|[^0-9])" ||
  ver =~ "^9\.9\.3(-P1|b[1-2]|rc[1-2])?$"
)
  fix = '9.9.3-P2';
else if (
  # Dev branches (no patch yet)
  # 9.8.6b1 / 9.8.6rc1, 9.9.4b1 / 9.9.4rc1
  # 9.9.4-S1b1 / 9.9.4-S1rc1 (DNSco)
  ver =~ "^9\.8\.6(b1|rc1)$" ||
  ver =~ "^9\.9\.4(b1|rc1)$" ||
  ver =~ "^9\.9\.4-S1(b1|rc1)$"
)
  fix = "See solution.";
else if (
  # Subscription from DNSco
  # 9.9.3-S1
  ver == "9.9.3-S1"
)
  fix = "9.9.3-S1-P1";
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
