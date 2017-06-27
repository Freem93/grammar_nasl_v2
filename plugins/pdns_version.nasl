#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34043);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/01/15 15:43:45 $");

 script_osvdb_id(23);

 script_name(english:"PowerDNS Version Detection");
 script_summary(english:"Sends a special request.");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote DNS server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running PowerDNS, an open source DNS server. It
was possible to extract the version number of the remote installation
by sending a special DNS request for the text 'version.pdns' in the
domain 'chaos'.");
 script_set_attribute(attribute:"solution", value:
"If desired, hide the version number of PowerDNS by modifying the
'version-string' option in pdns.conf or recursor.conf.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencies("dns_version.nasl");
 script_require_keys("dns_server/version");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 53;
version_source = get_kb_item_or_exit("dns_server/version");
if ("powerdns" >!< tolower(version_source))
  audit(AUDIT_NOT_LISTEN, "PowerDNS", port, "UDP");

version_txt_query = get_kb_item_or_exit("dns_server/version_txt_query");

version      = UNKNOWN_VER;
version_dev  = NULL;
version_full = NULL;
report_extra = NULL;

# 3.x
pattern = "^PowerDNS (Authoritative Server|Recursor) ([0-9.]+)(-[a-zA-Z0-9]+)?";
matches = eregmatch(pattern:pattern, string:version_source, icase:TRUE);

if (!isnull(matches))
{
  type    = matches[1];
  version = matches[2];
  if (!isnull(matches[3]))
    version_dev = matches[3];

  set_kb_item(name:"pdns/type", value:tolower(type));
  report_extra = '\n  Type           : ' + type;
}
# 2.x
else
{
  pattern = "Served by POWERDNS ([0-9.]+)(-[a-zA-Z0-9]+)?";
  matches = eregmatch(pattern:pattern, string:version_source, icase:TRUE);
  if (!isnull(matches))
  {
    version = matches[1];
    if (!isnull(matches[2]))
      version_dev = matches[2];
  }
}

version_full = version + version_dev;

set_kb_item(name:"pdns/version_source", value:version_source);
set_kb_item(name:"pdns/version",        value:version);
set_kb_item(name:"pdns/version_full",   value:version_full);
set_kb_item(name:"pdns/query/method",   value:version_txt_query);

if (report_verbosity > 0)
{
  report = 
    '\n  Query method   : ' + version_txt_query +
    '\n  Version source : ' + version_source +
    '\n  Version        : ' + version_full + 
    report_extra + 
    '\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
