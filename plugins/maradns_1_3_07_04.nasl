#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73478);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2008-0061");
  script_bugtraq_id(27124);
  script_osvdb_id(39842);

  script_name(english:"MaraDNS < 1.0.41 / 1.2.x < 1.2.12.08 / 1.3.x < 1.3.07.04 CNAME Record Resource Rotation Remote DoS");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by an issue during resource
record rotation. This issue could allow a remote attacker to send a
specially crafted packet, which will prevent an authoritative CNAME
record from resolving, resulting in a denial of service.

Note that if the line 'max_ar_chain = 2' is in the configuration file,
the host is not affected.");
  script_set_attribute(attribute:"see_also", value:"http://maradns.blogspot.com/2007/08/maradns-update-all-versions.html");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.0.41 / 1.2.12.08 / 1.3.07.04 or later or
refer to the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/29");
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

# < 1.0.41
if (version =~ "^(0|1\.0\.)" && ver_compare(ver:num_ver, fix:"1.0.41", strict:FALSE) == -1)
  fix = "1.0.41";

# 1.2.x < 1.2.12.08
else if (version =~ "^1\.[12]\." && ver_compare(ver:num_ver, fix:"1.2.12.08", strict:FALSE) == -1)
  fix = "1.2.12.08";

# 1.3.x < 1.3.07.04
else if (version =~ "^1\.3\." && ver_compare(ver:num_ver, fix:"1.3.07.04", strict:FALSE) == -1)
  fix = "1.3.07.04";

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
