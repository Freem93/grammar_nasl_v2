#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73481);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2011-0520");
  script_bugtraq_id(45966);
  script_osvdb_id(70630);

  script_name(english:"MaraDNS < 1.3.07.11 / 1.4.x < 1.4.06 / 2.0.x < 2.0.02 compress_add_dlabel_points Function Buffer Overflow");
  script_summary(english:"Checks version of MaraDNS server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is affected by a heap-based buffer overflow
due to improperly sanitizing user-supplied input submitted to the
compress_add_dlabel_points' function in the 'Compress.c' source file.
This issue could allow a remote attacker to crash the DNS server,
resulting in a denial of service or possibly code execution.");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/20110129.html");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/20110205.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=610834");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 1.3.07.11 / 1.4.06 / 2.0.02 or later or
apply the relevant patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/29");
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

# < 1.3.07.11
if (version =~ "^(0|1\.[0-3]\.)" && ver_compare(ver:num_ver, fix:"1.3.07.11", strict:FALSE) == -1)
  fix = "1.3.07.11";

# 1.4.x < 1.4.06
else if (version =~ "^1\.4\." && ver_compare(ver:num_ver, fix:"1.4.06", strict:FALSE) == -1)
  fix = "1.4.06";

# 2.x < 2.0.02
else if (version =~ "^2\.0\." && ver_compare(ver:num_ver, fix:"2.0.02", strict:FALSE) == -1)
  fix = "2.0.02";

else
  audit(AUDIT_LISTEN_NOT_VULN, "MaraDNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
