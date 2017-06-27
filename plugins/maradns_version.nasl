#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73473);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/11 18:59:48 $");

  script_name(english:"MaraDNS Server Version Detection");
  script_summary(english:"Leverages 'dns_server/version' KB info");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to obtain version information on the remote MaraDNS
server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to obtain version information from the remote MaraDNS
server by sending a special TXT record query to the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://maradns.samiam.org/");
  script_set_attribute(attribute:"solution", value:
"The 'debug_msg_level' or the 'no_fingerprint' variable in the MaraDNS
configuration file can be set to '0' to disable version queries if
desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:maradns:maradns");
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
appname = "MaraDNS";

dns_version = get_kb_item_or_exit("dns_server/version");

if ("MaraDNS" >!< dns_version) audit(AUDIT_NOT_LISTEN, appname, port, "UDP");

dns_version_query = get_kb_item_or_exit("dns_server/version_txt_query");
set_kb_item(name:"maradns/query/method", value:dns_version_query);

item = eregmatch(string:dns_version, pattern:"MaraDNS version (([0-9.]+)[a-zA-Z]?$)");
if (isnull(item)) audit(AUDIT_SERVICE_VER_FAIL, appname, port + " (UDP)");


full_ver = item[1];
num_ver  = item[2];

set_kb_item(name:"maradns/version", value:full_ver);
set_kb_item(name:"maradns/num_ver", value:num_ver);


if (report_verbosity > 0)
{
  report = '\n  Query method : ' + dns_version_query +
           '\n  Version      : ' + full_ver +
           '\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
