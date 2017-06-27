#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55049);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2011-1922");
  script_bugtraq_id(47986);
  script_osvdb_id(72750);
  script_xref(name:"CERT", value:"531342");

  script_name(english:"Unbound < 1.4.10 daemon/worker.c DNS Request Error Handling DoS");
  script_summary(english:"Checks version of Unbound.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Unbound DNS
resolver is affected by a denial of service vulnerability due improper
error handling. An unauthenticated, remote attacker can exploit this,
via a specially crafted DNS request, to cause an assertion failure and
a daemon exit, resulting in a denial of service condition. Note that
this vulnerability only exists when debugging functionality is enabled
(e.g. --enable-checking' or '--enable-debug') and the
interface-automatic option is turned on.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://unbound.nlnetlabs.nl/downloads/CVE-2011-1922.txt");
  # http://unbound.nlnetlabs.nl/pipermail/unbound-users/2011-May/001846.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c28f0fe");
  script_set_attribute(attribute:"solution", value:"Upgrade to Unbound version 1.4.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/25");
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

fixed_version = "1.4.10";
port = 53;

tcp = get_kb_item("DNS/tcp/53");
if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

# if version < 1.4.10
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-3]($|[^0-9])" ||
  version =~ "^1\.4(\.([0-9])(\.[0-9]+)*)?(([abp]|rc)[0-9]*)?$" ||
  version =~ "^1\.4\.10([ab]|rc)[0-9]*$"
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
