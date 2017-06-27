#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73477);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2007-3116");
  script_bugtraq_id(24337);
  script_osvdb_id(37016);

  script_name(english:"MaraDNS 1.2.12.06 / 1.3.05 Wildcard Resource Record Remote DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a memory leak issue when
handling wildcard records. This issue could allow a remote attacker to
cause a remote denial of service by querying for wildcard records.

Note that issue only affects hosts with 'bind_star_handling' set to
'2' in the configuration file.");
  # http://maradns.blogspot.com/2007/05/non-critical-memory-leak-plugged.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ed2f95c");
  script_set_attribute(attribute:"see_also", value:"http://comments.gmane.org/gmane.network.dns.maradns.general/1112");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/changelog-2006-2010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.2.12.07 / 1.3.06 or later, apply the
relevant patch, or refer to the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:maradns:maradns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("maradns_version.nasl");
  script_require_keys("maradns/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("maradns/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 53;
fix = NULL;

# Only 1.2.12.06 and 1.3.05 are affected
if (version == "1.2.12.06")
  fix = "1.2.12.07";

else if (version == "1.3.05")
  fix = "1.3.06";

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
