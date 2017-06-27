#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(87951);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2016/01/18 16:21:03 $");

 script_cve_id("CVE-2014-8601");
 script_bugtraq_id(71545);
 script_osvdb_id(115666);
 script_xref(name:"CERT", value:"264212");

 script_name(english:"PowerDNS Recursor 3.x < 3.6.2 Recursive Referral Handling DoS");
 script_summary(english:"Checks the PowerDNS Recursor version.");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS Recursor listening on the remote host is version 3.x prior to
3.6.2. It is, therefore, affected by a denial of service vulnerability
due to the lack of limiting delegation chaining. A remote attacker can
exploit this vulnerability, via a large or infinite number of
referrals, to cause resource exhaustion, resulting in a denial of
service condition.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.
Also, Nessus has not checked for the presence of the patch.");
 script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2014-02/");
 script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/264212");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS Recursor 3.6.2 or later. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date",value:"2014/12/08");
 script_set_attribute(attribute:"patch_publication_date",value:"2014/12/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:recursor");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

 script_family(english:"DNS");
 script_dependencies("pdns_version.nasl");
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

fix = '3.6.2';
port = 53;

# Only the Recursor is affected
type = get_kb_item_or_exit("pdns/type");
if (type != 'recursor') audit(AUDIT_NOT_LISTEN, app_name, port, "UDP");

if (version !~ "^3\." || (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0))
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
