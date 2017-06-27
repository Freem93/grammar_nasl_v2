#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87870);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/13 14:56:53 $");

  script_cve_id("CVE-2014-8602");
  script_bugtraq_id(71589);
  script_osvdb_id(115667);
  script_xref(name:"CERT", value:"264212");

  script_name(english:"Unbound < 1.5.1 Delegation Handling Recursive Referral Handling Resource Exhaustion DoS");
  script_summary(english:"Checks version of Unbound.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Unbound DNS
resolver is affected by a denial of service vulnerability in the
Domain Name Service due to improper handling of a
maliciously-constructed zone or queries from a rogue server. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause the service to issue unlimited queries in an
attempt to follow a delegation, resulting in a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"https://unbound.net/downloads/CVE-2014-8602.txt");
  script_set_attribute(attribute:"see_also", value:"http://unbound.net/downloads/patch_cve_2014_8602.diff");
  # Note: when the manual patch is applied, Unbound will identify
  # itself as the base version. E.g. if 1.5.0 is manually patched,
  # it will still identify itself as "unbound 1.5.0" (no 'p' suffix)
  script_set_attribute(attribute:"solution", value:
"Upgrade to Unbound version 1.5.1 or later. Alternatively, apply the
patch provided by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:unbound:unbound");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("unbound_version.nasl");
  script_require_keys("Settings/ParanoidReport","unbound/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("unbound/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_version = "1.5.1";
port = 53;

tcp = get_kb_item("DNS/tcp/53");
if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

# if version < 1.5.1 (including patches and rc)
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-4]($|[^0-9])" ||
  version =~ "^1\.5(\.0(\.[0-9]+)*)?(([abp]|rc)[0-9]*)?$" ||
  version =~ "^1\.5\.1([ab]|rc)[0-9]*$"
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
else audit(AUDIT_LISTEN_NOT_VULN, "Unbound", port, version);
