#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(87946);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2016/01/18 16:21:03 $");

 script_cve_id("CVE-2015-1868", "CVE-2015-5470");
 script_bugtraq_id(74306);
 script_osvdb_id(121235);

 script_name(english:"PowerDNS Authoritative Server 3.x < 3.4.5 Label Decompression Self-Referential Name Handling DoS");
 script_summary(english:"Checks the PowerDNS Authoritative Server version.");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS Authoritative Server listening on the remote host is version
3.x prior to 3.4.5. It is, therefore, affected by a denial of service
vulnerability due to improper validation of user-supplied input when
handling self-referential names during label decompression. An
unauthenticated, remote attacker can exploit this, via specially
crafted query packets, to crash the server.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of the patch.");
 script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2015-01/");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Authoritative Server 3.4.5 or later.
Alternatively, apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date",value:"2015/04/23");
 script_set_attribute(attribute:"patch_publication_date",value:"2015/06/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:authoritative");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

 script_family(english:"DNS");
 script_dependencies("pdns_version.nasl");
 script_require_keys("pdns/version_full", "pdns/version_source", "pdns/type", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS Authoritative Server";
version_source = get_kb_item_or_exit("pdns/version_source");
version = get_kb_item_or_exit("pdns/version_full");

fix = '3.4.5';
port = 53;

# Only the Authoritative Server is affected
type = get_kb_item_or_exit("pdns/type");
if (type != 'authoritative server') audit(AUDIT_NOT_LISTEN, app_name, port, "UDP");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);


if (version =~ "^3\.[23]([^0-9]|$)" || version =~ "^3\.4(\.[0-4])?([^0-9.]|$)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + version_source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, proto:"udp", extra:report);
  }
  else security_hole(port:port, proto:"udp");
}
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, "UDP");
