#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(87872);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2016/01/12 15:53:16 $");

 script_name(english:"Unbound DNS Resolver Remote Version Detection");
 script_summary(english:"Leverages 'dns_server/version' KB info.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version number of the remote DNS server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Unbound DNS resolver. 

Note that the version detected is not necessarily accurate and could
even be forged, as some DNS servers send the information based on a
configuration file.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"see_also", value:"https://www.unbound.net/");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:unbound:unbound");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencies("dns_version.nasl");
 script_require_keys("dns_server/version");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dns_version = get_kb_item_or_exit("dns_server/version");
dns_version_query = tolower(get_kb_item_or_exit("dns_server/version_txt_query"));

app_name = "Unbound";
port = 53;

pattern = app_name + " +([0-9]+[^ ]*)"; # "Unbound +([0-9]+[^ ]*)"
match = eregmatch(pattern:pattern, string:dns_version, icase:TRUE);

if (isnull(match)) audit(AUDIT_NOT_LISTEN, app_name, port);
unbound_version = match[1];

set_kb_item(name:"unbound/version", value:unbound_version);
set_kb_item(name:"dns/unbound/"+port, value:TRUE);
set_kb_item(name:"dns/unbound/"+port+"/source", value:dns_version_query);
set_kb_item(name:"dns/unbound/"+port+"/version", value:dns_version);

tcp = get_kb_item("DNS/tcp/53");

if (!isnull(tcp)) proto = "tcp";
else proto = "udp"; # default

report = '\n  Version : ' + dns_version + '\n';
if (report_verbosity > 0)
  security_note(port:port, proto:proto, extra:report);
else
  security_note(port:port, proto:proto);
