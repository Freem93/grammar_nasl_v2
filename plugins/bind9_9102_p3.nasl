#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85241);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/13 04:38:20 $");

  script_cve_id("CVE-2015-5477");
  script_osvdb_id(125438);
  script_xref(name:"EDB-ID", value:"37721");

  script_name(english:"ISC BIND 9.7.x < 9.9.7-P2 / 9.10.x < 9.10.2-P3 TKEY Query Handling Remote DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND on the remote name server is potentially affected by a denial
of service vulnerability due to a REQUIRE assertion flaw that occurs
while handling TKEY queries. A remote attacker can exploit this by
using a specially crafted TKEY query to crash the daemon.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01272");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01279");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01280");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.7-P2 / 9.10.2-P3 or later, or apply the
patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");

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

# 9.1.0 through BIND 9.9.7-P1 and BIND 9.10.2-P2 are vulnerable
if (
  ver =~ "^9\.[1-8]([^0-9]|$)" ||
  ver =~ "^9\.9\.[0-6]([^0-9]|$)" ||
  ver =~ "^9\.9\.7($|([ab][12]|rc[12]|-P1)$)"
) fix = '9.9.7-P2';

if (
  ver =~ "^9\.10\.[01]([^0-9]|$)" ||
  ver =~ "^9\.10\.2($|([ab][12]|rc[12]|-P[12])$)"
) fix = '9.10.2-P3';

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
