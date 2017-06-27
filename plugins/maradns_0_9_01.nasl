#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73474);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2002-2097");
  script_bugtraq_id(3852);
  script_osvdb_id(19755);

  script_name(english:"MaraDNS 0.5.x < 0.5.31 / 0.9.x < 0.9.01 Compression Code Remote DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a memory leak issue due to
the compression code. This issue could allow a remote attacker to
cause a remote denial of service by sending a specially crafted DNS
packet.");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=maradns-list&m=101173460805872");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/changelog-2001-2005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 0.9.01 or later or apply the relevant
patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/10");
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

# 0.5.x < 0.5.31
if (version =~ "^0\.5\." && ver_compare(ver:num_ver, fix:"0.5.31", strict:FALSE) == -1)
  fix = "0.5.31";

# 0.9.x < 0.9.01
else if (version =~ "^0\.9\." && ver_compare(ver:num_ver, fix:"0.9.01", strict:FALSE) == -1)
  fix = "0.9.01";

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
