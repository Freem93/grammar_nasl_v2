#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73479);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/20 16:45:01 $");

  script_cve_id("CVE-2010-2444");
  script_bugtraq_id(40745);
  script_osvdb_id(65805);

  script_name(english:"MaraDNS 1.3.03 to 1.3.07.10 / 1.4.x < 1.4.03 NULL Pointer Dereference Local DoS (Linux)");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a NULL pointer dereference
issue due to improper handling of hostnames not ending with a dot
character in 'csv2' zone files. This issue could allow a remote
attacker to crash the DNS server, resulting in a denial of service.");
  # http://maradns.blogspot.com/2010/02/maradns-1403-and-130710-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd837053");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.3.07.10 / 1.4.03 or later or apply the
relevant patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
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

# 1.3.03 -  1.3.07.10
if (
  version =~ "^1\.3\.0[3-6]([^0-9]|$)" ||
  version =~ "^1\.3\.07\.0?[0-9]([^0-9]|$)"
)
  fix = "1.3.07.10";

# 1.4.x < 1.4.03
else if (version =~ "^1\.4\." && ver_compare(ver:num_ver, fix:"1.4.03", strict:FALSE) == -1)
  fix = "1.4.03";

else
  audit(AUDIT_LISTEN_NOT_VULN, "MaraDNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
