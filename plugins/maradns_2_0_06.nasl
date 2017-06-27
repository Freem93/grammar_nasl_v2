#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73483);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2012-1570");
  script_bugtraq_id(52558);
  script_osvdb_id(80192);

  script_name(english:"MaraDNS < 1.3.07.15 / 1.4.x < 1.4.12 / 2.0.x < 2.0.06 Persistent Ghost Domain Caching");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a domain
caching vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by an issue when updating DNS
records in the server's cache that were revoked, possibly for
malicious reasons. A remote attacker can continually query an affected
host for the revoked domain, resulting in the domain name still
resolving. This type of attack is known as a 'ghost domain' attack.");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/20120322.html");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/20120213.html");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.3.07.15 / 1.4.12 / 2.0.06 or later or
apply the relevant patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:maradns:maradns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("maradns_version.nasl");
  script_require_keys("maradns/version", "maradns/num_ver", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("maradns/version");
num_ver = get_kb_item_or_exit("maradns/num_ver");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 53;
fix = NULL;

# < 1.3.07.15
if (version =~ "^(0|1\.[0-3])\." && ver_compare(ver:num_ver, fix:"1.3.07.15", strict:FALSE) == -1)
  fix = "1.3.07.15";

# 1.4.x < 1.4.12
else if (version =~ "^1\.4\." && ver_compare(ver:num_ver, fix:"1.4.12", strict:FALSE) == -1)
  fix = "1.4.12";

# 2.x < 2.0.06
else if (version =~ "^2\.0\." && ver_compare(ver:num_ver, fix:"2.0.06", strict:FALSE) == -1)
  fix = "2.0.06";

else
  audit(AUDIT_LISTEN_NOT_VULN, "MaraDNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
