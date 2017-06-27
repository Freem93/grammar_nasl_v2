#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10028);
 script_version("$Revision: 1.54 $");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");

 script_osvdb_id(23);

 script_name(english:"DNS Server BIND version Directive Remote Version Detection");
 script_summary(english:"Leverages 'dns_server/version' KB info");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the version number of the remote DNS server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running BIND or another DNS server that reports its
version number when it receives a special request for the text
'version.bind' in the domain 'chaos'. 

This version is not necessarily accurate and could even be forged, as
some DNS servers send the information based on a configuration file.");
 script_set_attribute(attribute:"solution", value:
"It is possible to hide the version number of BIND by using the
'version' directive in the 'options' section in named.conf.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencies("dns_version.nasl");
 script_require_keys("dns_server/version");
 exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 53;

dns_version = get_kb_item_or_exit("dns_server/version");

dns_version_query = tolower(get_kb_item_or_exit("dns_server/version_txt_query"));
if (
  dns_version_query != "version.bind" && 
  dns_version_query != "version.server"
) audit(AUDIT_NOT_LISTEN, "BIND", port, "UDP");

# NSD will also respond to VERSION.BIND requests. make sure this isn't NSD.
# Also, BIND doesn't prefix anything to its version string, which should start
# with a numeral
if ("nsd" >< tolower(dns_version)) audit(AUDIT_NOT_LISTEN, "BIND", port, "UDP");
if (dns_version !~ "^[0-9]+\.") audit(AUDIT_NOT_LISTEN, "BIND", port, "UDP");

set_kb_item(name:"bind/version", value:dns_version);

report = '\n  Version : ' + dns_version + 
         '\n';
if (report_verbosity > 0) security_note(port:port, proto:"udp", extra:report);
else security_note(port:port, proto:"udp");
