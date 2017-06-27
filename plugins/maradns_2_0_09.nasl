#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73484);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2014-2031", "CVE-2014-2032");
  script_bugtraq_id(65595, 65689);
  script_osvdb_id(103418);

  script_name(english:"MaraDNS < 1.4.14 / 2.0.x < 2.0.09 Deadwood Out-of-Bounds DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host may be running a version of Deadwood, a
recursive resolver bundled with MaraDNS, which is affected by an
out-of-bounds read error. This issue exists due to the lack of bounds
checking in the 'DwCompress.c' and 'DwRecurse.c' source files. This
issue could allow a remote attacker to crash the recursive DNS
resolver, resulting in a denial of service.

Note that this only affects the Deadwood component.");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/2014-02-12.html");
  # https://github.com/samboy/MaraDNS/commit/2cfcd2397cb8168d4aa4594839fabe88420d03c3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b1b677d");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MaraDNS version 1.4.14 / 2.0.09 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
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

# Only affects Deadwood, which is bundled with MaraDNS
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 53;
fix = NULL;

# < 1.4.14
if (version =~ "^(0|1\.[0-4])\." && ver_compare(ver:num_ver, fix:"1.4.14", strict:FALSE) == -1)
  fix = "1.4.14";

# 2.x < 2.0.09
else if (version =~ "^2\.0\." && ver_compare(ver:num_ver, fix:"2.0.09", strict:FALSE) == -1)
  fix = "2.0.09";

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
