#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34044);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/01/15 15:43:45 $");

 script_cve_id("CVE-2008-1637", "CVE-2008-3217");
 script_bugtraq_id(28517, 30782);
 script_osvdb_id(43905);

 script_name(english:"PowerDNS Recursor 3.x < 3.1.6 DNS Predictable Transaction ID (TRXID) Cache Poisoning");
 script_summary(english:"Checks the version of PowerDNS Recursor.");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a cache poisoning vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PowerDNS
Recursor listening on the remote host is version 3.x prior to 3.1.6.
It is, therefore, affected by a cache poisoning vulnerability due to
insufficient randomness to calculate TRXID values and UDP source port
numbers. A remote attacker can exploit this poison the DNS cache. This
vulnerability was originally fixed in version 3.1.5, but a more secure
method was implemented in version 3.1.6.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of the patch or the
workaround.");
 script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/changelog/#recursor-version-316");
 script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2008-01/");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS recursor 3.1.6 or later. Alternatively, apply the
patch referenced in the vendor advisory..");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:recursor");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencies("pdns_version.nasl");
 script_require_keys("pdns/version", "pdns/version_full", "pdns/version_source", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS Recursor";
version_source = get_kb_item_or_exit("pdns/version_source");
version_full = get_kb_item_or_exit("pdns/version_full");
version = get_kb_item_or_exit("pdns/version");
type = get_kb_item_or_exit("pdns/type");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '3.1.6';
port = 53;

if (type != 'recursor')
  audit(AUDIT_NOT_LISTEN, "PowerDNS Recursor", port, "UDP");


if (version !~ "^3\." || ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
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
