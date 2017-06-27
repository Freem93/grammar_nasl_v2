#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73945);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/28 21:57:28 $");

  script_cve_id("CVE-2014-3214");
  script_bugtraq_id(67311);
  script_osvdb_id(106800);

  script_name(english:"ISC BIND 9 Recursive Server prefetch DoS");
  script_summary(english:"Checks version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by a denial of service vulnerability. The issue
exists due to an error in the 'prefetch' feature which can cause named
to terminate with a 'REQUIRE' assertion failure if it processes
queries whose answers have particular attributes.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01161");
  script_set_attribute(attribute:"see_also", value:"https://deepthought.isc.org/article/AA-01162");
  script_set_attribute(attribute:"see_also", value:"https://lists.isc.org/pipermail/bind-announce/2014-May/000909.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.10.0-P1 or later.

Alternatively, in 'named.conf', set the 'prefetch' option to '0'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
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

# Vuln BIND 9.10.0.x < 9.10.0-P1
if (ver =~ "^9\.10\.0($|([ab][12]|rc[12])$)")
  fix = '9.10.0-P1';
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
