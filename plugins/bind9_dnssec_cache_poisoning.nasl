#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42983);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/05/25 01:37:06 $");

  script_cve_id("CVE-2009-4022", "CVE-2010-0382");
  script_bugtraq_id(37118);
  script_osvdb_id(60493, 62008);
  script_xref(name:"CERT", value:"418861");

  script_name(english:"ISC BIND 9 DNSSEC Cache Poisoning");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is affected by a cache poisoning vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of BIND
suffers from a cache poisoning vulnerability. This issue affects all
versions prior to 9.4.3-P5, 9.5.2-P2 or 9.6.1-P3.

Note that only nameservers that allow recursive queries and validate
DNSSEC records are affected. Nessus has not attempted to verify if
this configuration applies to the remote service, though, so this
could be a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/advisories/CVE2009-4022");
  script_set_attribute(attribute:"see_also", value:"http://www.vupen.com/english/advisories/2010/1352");
  script_set_attribute(attribute:"see_also", value:"http://www.vupen.com/english/advisories/2010/0622");
  script_set_attribute(attribute:"see_also", value:"http://www.vupen.com/english/advisories/2009/3335");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.4.3-P5 / 9.5.2-P2 / 9.6.1-P3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl", "dnssec_resolver.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item("bind/version");
if (!ver) exit(1, "BIND version is unknown or DNS is not running.");

# Versions affected:
# 9.0.x, 9.1.x, 9.2.x, 9.3.x, 9.4.0-9.4.3-P3, 9.5.0, 9.5.1, 9.5.2, 9.6.0, 9.6.1-P1

pattern = "^(" +
          "9\.4-ESVb1|" +
          "9\.4\.([0-2]([^0-9]|$)|3(-P[1-4]$|[^0-9\-]|$))|"+
          "9\.5\.([01]([^0-9]|$)|2(-P1$|[^0-9\-]|$))|" +
          "9\.6\.(0([^0-9]|$)|1(-P[1-2]$|[^0-9\-]|$)|2b1$)|" +
          "9\.7\.0([ab][0-3]$|rc1$)" + ")";

if (ver =~ "^9\.[0-3]\.")
{
  security_note(port:53, proto:"udp", extra:
'\nNo fix is available on branches 9.0 to 9.3 (end of life).');
  exit(0);
}
if (ereg(pattern:pattern, string:ver) )
  security_note(port:53, proto:"udp");
else
  exit(0, "BIND version "+ ver + " is running on port 53 and is not vulnerable.");

