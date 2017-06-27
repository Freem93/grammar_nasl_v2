#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77780);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/15 15:43:45 $");

  script_cve_id("CVE-2014-3614");
  script_bugtraq_id(69778);
  script_osvdb_id(111269);

  script_name(english:"PowerDNS Recursor 3.6.0 Packet Sequence Handling DoS");
  script_summary(english:"Checks the version of PowerDNS Recursor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS Recursor service listening on the remote host is version
3.6.0. It is, therefore, affected by a denial of service vulnerability
due to improper handling of malformed packet sequences. An
unauthenticated, remote attacker can exploit this to crash the
application, resulting in a denial of service condition.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of the patch or the
workaround.");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2014-01/");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/html/changelog.html#changelog-recursor-3.6.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Recursor 3.6.1 or later. Alternatively, apply the
patch or workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns_recursor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("pdns_version.nasl");
  script_require_keys("pdns/version_full", "pdns/version_source", "pdns/type", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS Recursor";
version_source = get_kb_item_or_exit("pdns/version_source");
version_full = get_kb_item_or_exit("pdns/version_full");
type = get_kb_item_or_exit("pdns/type");

fix = '3.6.1';
port = 53;

# Only the Recursor is affected
if (type != 'recursor')
  audit(AUDIT_NOT_LISTEN, app_name, port, "UDP");

if (version_full == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version_full !~ "^3\.6(\.0)?($|[^0-9.])")
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
