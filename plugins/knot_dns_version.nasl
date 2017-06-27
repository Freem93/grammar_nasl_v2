#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76798);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/06 15:17:46 $");

  script_name(english:"Knot DNS Server Version Detection");
  script_summary(english:"Leverages 'dns_server/version' KB info.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to obtain version information on the remote Knot DNS
server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to obtain version information from the remote Knot DNS
server by sending a special TXT record query to the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.knot-dns.cz/");
  script_set_attribute(attribute:"solution", value:
"Version reporting may be disabled by setting the 'version' attribute
to 'off' in the 'system' statement of the Knot DNS configuration file.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cz.nic:knot_dns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("dns_version.nasl");
  script_require_keys("dns_server/version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 53;
appname = "Knot DNS";

dns_version = get_kb_item_or_exit("dns_server/version");
is_tcp = get_kb_item("DNS/tcp/"+port);
if (!empty_or_null(is_tcp)) proto = "TCP";
else proto = "UDP";

if ("Knot DNS" >!< dns_version) audit(AUDIT_NOT_LISTEN, appname, port, proto);

dns_version_query = get_kb_item_or_exit("dns_server/version_txt_query");
set_kb_item(name:"knot_dns/query/method", value:dns_version_query);

item = eregmatch(string:dns_version, pattern:"Knot DNS (([0-9.]+)(-[a-zA-Z0-9]+)?$)");
if (isnull(item)) audit(AUDIT_SERVICE_VER_FAIL, appname, port + " ("+proto+")");

full_ver = item[1];
num_ver  = item[2];

set_kb_item(name:"knot_dns/proto", value:proto);
set_kb_item(name:"knot_dns/"+proto+"/version", value:full_ver);
set_kb_item(name:"knot_dns/"+proto+"/num_ver", value:num_ver);

if (report_verbosity > 0)
{
  report = '\n  Query method : ' + dns_version_query +
           '\n  Version      : ' + full_ver +
           '\n';
  security_note(port:port, proto:tolower(proto), extra:report);
}
else security_note(port:port, proto:tolower(proto));
