#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69429);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/15 15:43:45 $");

  script_cve_id("CVE-2012-1193");
  script_bugtraq_id(59348);
  script_osvdb_id(79439);

  script_name(english:"PowerDNS Recursor 3.3.x / 3.4.x / 3.5 RC1 Cache Update Policy Deleted Domain Name Resolving Weakness");
  script_summary(english:"Checks the version of PowerDNS Recursor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a ghost domain names
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS Recursor service listening on the remote host is 3.3.x,
3.4.x, or 3.5 RC1. It is, therefore, affected by a ghost domain names
vulnerability in the resolver service due to overwriting cached name
servers and TTL values in NS records when processing a response of an
A record query. A remote attacker can exploit this to resume the
resolving of revoked domain names.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://wiki.powerdns.com/trac/ticket/668");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/changelog/#powerdns-recursor-version-35");
  script_set_attribute(attribute:"see_also", value:"http://wiki.powerdns.com/trac/changeset/3085");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Recursor 3.5.0 or later. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:recursor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencie("pdns_version.nasl");
  script_require_keys("pdns/version", "pdns/version_full", "pdns/version_source", "pdns/type", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS Recursor";
version_source = get_kb_item_or_exit("pdns/version_source");
version_full = get_kb_item_or_exit("pdns/version_full");
version = get_kb_item_or_exit("pdns/version");

fix = '3.5.0';
port = 53;

# Only the Recursor is affected
type = get_kb_item_or_exit("pdns/type");
if (type != 'recursor') audit(AUDIT_NOT_LISTEN, app_name, port, "UDP");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);


if (version !~ "^3\.[34]([^0-9]|$)" && version_full !~ "^3\.5(\.0)?-RC1([^0-9]|$)")
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version_full, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + version_source +
    '\n  Installed version : ' + version_full +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
