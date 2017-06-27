#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86674);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(128200);

  script_name(english:"MaraDNS < 2.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MaraDNS server.");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the MaraDNS server
running on the remote host is prior to 2.0.13. It is, therefore,
potentially affected by multiple vulnerabilities :

  - A flaw exists in mararc parser due to a buffer underflow
    condition in the file ParseMaraRc.c. An unauthenticated,
    remote attacker can exploit this to read from disallowed
    memory locations.

  - A flaw exists in the Deadwood recursive resolver
    component due to a buffer underflow condition that can
    allow an out-of-bounds memory location to be overwritten
    by the output of malloc(). An unauthenticated, remote
    attacker can exploit this issue to cause a denial of
    service. (VulnDB 128200)");
  script_set_attribute(attribute:"see_also", value:"http://samiam.org/blog/2015-10-08.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/samboy/MaraDNS/issues/19");
  script_set_attribute(attribute:"see_also", value:"https://github.com/samboy/MaraDNS/issues/20");
  script_set_attribute(attribute:"see_also", value:"https://github.com/samboy/MaraDNS/issues/21");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MaraDNS version 2.0.13 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:maradns:maradns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

# < 2.0.13
if ( ver_compare(ver:num_ver, fix:"2.0.13", strict:FALSE) == -1 )
  fix = "2.0.13";
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
