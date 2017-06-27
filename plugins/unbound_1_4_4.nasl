#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55048);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/12 15:53:16 $");

  script_cve_id("CVE-2009-4008");
  script_bugtraq_id(48209);
  script_osvdb_id(73253);

  script_name(english:"Unbound < 1.4.4 Unbound Signed Zone Query Response DNSSEC Outage DoS");
  script_summary(english:"Checks version of Unbound.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Unbound DNS
resolver is affected by a denial of service vulnerability due to a
failure to send responses for signed zones after mishandling an
unspecified query. An attacker can exploit this, via a crafted query,
to cause a DNSSEC outage, resulting in a denial of service condition.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Unbound version 1.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unbound:unbound");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("unbound_version.nasl");
  script_require_keys("unbound/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("unbound/version");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_version = "1.4.4";
port = 53;

tcp = get_kb_item("DNS/tcp/53");
if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

# if version < 1.4.4
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-3]($|[^0-9])" ||
  version =~ "^1\.4(\.([0-3])(\.[0-9]+)*)?(([abp]|rc)[0-9]*)?$" ||
  version =~ "^1\.4\.4([ab]|rc)[0-9]*$"
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
