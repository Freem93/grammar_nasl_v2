#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73482);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2011-5056");
  script_osvdb_id(78280);

  script_name(english:"MaraDNS 2.0.x < 2.0.05 Hash Collision Zone File Record Local DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a hash collision issue when
parsing records in zone files. This issue could allow a local attacker
to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/20120212.html");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MaraDNS version 2.0.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/12");
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

# 2.0.x < 2.0.05
if (version =~ "^2\.0\." && ver_compare(ver:num_ver, fix:"2.0.05", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.05' +
      '\n';
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
else
  audit(AUDIT_LISTEN_NOT_VULN, "MaraDNS", port, version, "UDP");
