#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52158);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/25 01:37:06 $");

  script_cve_id("CVE-2011-0414");
  script_bugtraq_id(46491);
  script_osvdb_id(72539);
  script_xref(name:"CERT", value:"559980");
  script_xref(name:"Secunia", value:"43443");

  script_name(english:"ISC BIND 9.7.1-9.7.2-P3 IXFR / DDNS Update Combined with High Query Rate DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by a denial of service vulnerability.

There is a small window of time after an authoritative server
processes a successful IXFR transfer or a dynamic update during which
the IXFR / update coupled with a query may cause a deadlock to occur.
A server experiencing a high query and/or update rate will have a
higher chance of being deadlocked.");

  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2011-0414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.7.3 or later.

A possible workaround is to restrict BIND to a single worker thread,
using the '-n1' flag for example.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("bind/version");
if (version =~ '^9\\.7\\.(1|2([^0-9\\-]|$|-P[0-3]([^0-9]|$)))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.7.3\n';
    security_hole(port:53, proto:"udp", extra:report);
  }
  else security_hole(port:53, proto:"udp");
  exit(0);
}
else exit(0, 'BIND version ' + version + ' is running on port 53 and thus is not affected.');
