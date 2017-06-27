#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57573);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-0206");
  script_bugtraq_id(51355);
  script_osvdb_id(78251);

  script_name(english:"PowerDNS Authoritative Server < 2.9.22.5 / 3.0.1 Response Packet Parsing DoS");
  script_summary(english:"Checks the version of PowerDNS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the 
PowerDNS service listening on the remote host is prior to 2.9.22.5 or
3.0.1. It is, therefore, affected by a denial of service vulnerability
due to improper handling of response packets. A remote attacker can
exploit this, via a specially crafted packet, to tagger an infinite
packet response loop, resulting in a denial of service condition.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of any of the
workarounds or if a patch is applied. Furthermore, for versions prior
to 3.x, Nessus did not check if the server is operating as an
authoritative server.");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/powerdns-advisory-2012-01.html");
  # http://mailman.powerdns.com/pipermail/pdns-announce/2012-January/000152.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c15fb8b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Authoritative Server 2.9.22.5 / 3.0.1 or later.
Alternatively, apply one of the workarounds or patches referenced in
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:authoritative");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("pdns_version.nasl");
  script_require_keys("pdns/version", "pdns/version_full", "pdns/version_source", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS";
version_source = get_kb_item_or_exit("pdns/version_source");
version = get_kb_item_or_exit("pdns/version");
version_full = get_kb_item_or_exit("pdns/version_full");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 53;
fix = NULL;

# Only PowerDNS Authoritative Server is affected but we can only determine this in 3.x
type = get_kb_item("pdns/type");
if (!isnull(type) && type != 'authoritative server')
  audit(AUDIT_NOT_LISTEN, "PowerDNS Authoritative Server", port, "UDP");


if (version =~ "^3\.")
  fix = "3.0.1";
else
  fix = "2.9.22.5";

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version_full, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + version_source +
    '\n  Installed version : ' + version_full +
    '\n  Fixed version     : 2.9.22.5 / 3.0.1'  +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
