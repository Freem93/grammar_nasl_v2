#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88385);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2015-8704", "CVE-2015-8705");
  script_osvdb_id(133380, 133381);

  script_name(english:"ISC BIND 9.3.0 < 9.9.8-P3 / 9.9.x-Sx < 9.9.8-S4 / 9.10.x < 9.10.3-P3 Multiple DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND running on the remote name server is affected by multiple
denial of service vulnerabilities :

  - A denial of service vulnerability exists due to improper
    handling of certain string formatting options. An
    authenticated, remote attacker can exploit this, via a
    malformed Address Prefix List (APL) record, to cause an
    INSIST assertion failure and daemon exist.
    (CVE-2015-8704)

  - A denial of service vulnerability exists due to a
    failure to properly convert OPT records and ECS options
    to formatted text. A remote attacker can exploit this
    to cause a REQUIRE assertion failure and daemon exit.
    Note that this issue only affects BIND 9.10.x.
    (CVE-2015-8705)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01335");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01336");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.8-P3 / 9.9.8-S4 / 9.10.3-P3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (
  ver =~ '^9\\.[3-8]([^0-9]|$)' ||
  ver =~ '^9\\.9\\.[0-7]([^0-9]|$)' ||
  ver =~ '^9\\.9\\.8($|[^0-9\\-]|-P[0-2]([^0-9]|$))'
) fix = '9.9.8-P3';
else if (
  ver =~ '^9\\.9\\.(3-S[1-9]|[4-7]-S[0-9]|8-S[0-3])([^0-9]|$)'
) fix = '9.9.8-S4';  
else if (
  ver =~ '^9\\.10\\.[0-2]([^0-9]|$)' ||
  ver =~ '^9\\.10\\.3($|[^0-9\\-]|-P[0-2]([^0-9]|$))'
) fix = '9.10.3-P3';

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
