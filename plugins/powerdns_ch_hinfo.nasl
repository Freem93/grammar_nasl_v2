#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35375);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/01/15 15:43:45 $");

 script_cve_id("CVE-2008-5277");
 script_bugtraq_id(32627);
 script_osvdb_id(50458);

 script_name(english:"PowerDNS Authoritative Server < 2.9.21.2 CH HINFO Query Handling DoS");
 script_summary(english:"Checks the version of PowerDNS.");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS service listening on the remote host is prior to 2.9.21.2. It
is, therefore, affected by a denial of service vulnerability when
processing specially crafted CH HINFO queries. A remote attacker can
exploit this to crash the server.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of a workaround,
the presence of a patch, or if the server is operating as an
authoritative server.");
 script_set_attribute(attribute:"see_also", value:"http://doc.powerdns.com/md/security/powerdns-advisory-2008-03/");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS version 2.9.21.2 or later. Alternatively, apply
the patch or workaround referenced in the vendor advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/11/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:authoritative");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencie("pdns_version.nasl");
 script_require_keys("pdns/version", "pdns/version_full", "pdns/version_source", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS";
version_source = get_kb_item_or_exit("pdns/version_source");
version_full = get_kb_item_or_exit("pdns/version_full");
version = get_kb_item_or_exit("pdns/version");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '2.9.21.2';
port = 53;

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
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
