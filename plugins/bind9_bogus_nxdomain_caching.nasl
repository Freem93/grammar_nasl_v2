#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44116);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-0097");
  script_bugtraq_id(37865);
  script_osvdb_id(61853);
  script_xref(name:"CERT", value:"360341");
  script_xref(name:"Secunia", value:"38219");

  script_name(english:"ISC BIND 9 DNSSEC NSEC/NSEC3 Bogus NXDOMAIN Responses");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a cache poisoning
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of BIND
suffers from a cache poisoning vulnerability.  The vulnerability
exists due to an error in DNSSEC NSEC/NSEC3 validation code which
could cause caching of bogus NXDOMAIN responses without correctly
validating them.  This issue affects all versions prior to 9.4.3-P5,
9.5.2-P2, 9.6.1-P3 or pre-releases of 9.7.0. 

Note that only nameservers that allow recursive queries and validate
DNSSEC records are affected.  Nessus has tried to verify if the remote
service supports DNSSEC options, but has not verified if the remote
service allows recursive queries, so this could be a false positive."
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4.3-P5, 9.5.2-P2 or 9.6.1-P3 or later. 

Note that fixes for 9.7.0 pre-releases are not available as of
2010/01/22."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",   value:"2010/01/19");
  script_set_attribute(attribute:"patch_publication_date",  value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english: "DNS");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl", "dnssec_resolver.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");

if (report_paranoia < 2) 
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

ver = get_kb_item("bind/version");
if (!ver) exit(1, "The 'bind/version' KB item is missing.");

# nb: don't bother if the host doesn't support DNSSEC.
if (isnull(get_kb_item("DNSSEC/udp/53"))) 
  exit(0,"The remote BIND server does not support DNSSEC.");

# Versions affected: 
# 9.0.x, 9.1.x, 9.2.x, 9.3.x, 9.4.0 -> 9.4.3-P4, 9.5.0 -> 9.5.2-P1, 9.6.0 -> 9.6.1-P2 
# 9.7.0 pre-releases are also affected.

pattern = "^(" +
        "9\.4-ESVb1|" +
        "9\.4\.([0-2]([^0-9]|$)|3(-P[1-4]$|[^0-9\-]|$))|"+
        "9\.5\.([01]([^0-9]|$)|2(-P1$|[^0-9\-]|$))|" +
        "9\.6\.(0([^0-9]|$)|1(-P[1-2]$|[^0-9\-]|$)|2b1$)|" +
        "9\.7\.0([ab][0-3]$|rc1$)" + ")";

if (ver =~ "^9\.[0-3]\.")
{
  security_warning(port:53, proto:"udp", extra:
'\nNo fix is available on branches 9.0 to 9.3 (end of life).');
  exit(0);
}
if (ereg(pattern:pattern, string:ver) )
{
  if(report_verbosity > 0)
  {
    report = '\n' + 
    "  BIND version " + ver + " is running on the remote host." + 
    '\n';
    security_warning(port:53, proto:"udp",extra:report);
  }
  else
    security_warning(port:53, proto:"udp");

  exit(0);
} 
else
  exit(0, "BIND version "+ ver + " is running on port 53 and is not vulnerable.");
