#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72780);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/03/03 22:09:44 $");

  script_name(english:"Microsoft DNS Server Version Detection");
  script_summary(english:"Leverages 'dns_server/version' KB info");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus was able to obtain version information on the remote Microsoft
DNS server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to obtain version information from the remote Microsoft
DNS server by sending a special TXT record query to the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc772069.aspx");
  script_set_attribute(
    attribute:"solution",
    value:
"The command 'dnscmd /config /EnableVersionQuery 0' can be used to
disable version queries if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
if ("Microsoft DNS" >!< dns_version) audit(AUDIT_NOT_LISTEN, "Microsoft DNS Server", port, "UDP");

item = eregmatch(string:dns_version,
                 pattern:"Microsoft DNS ([0-9]+\.[0-9]+\.[0-9]+) \(([0-9A-Za-z]+)\)");

# ms dns will respond to any query with "version." in the name,
# so we have to check the response.
if (!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
{
  version = item[1];
  ver = split(version, sep:'.', keep:FALSE);

  tmp = hex2raw(s:item[2]);

  # can be used to do a sanity check with in full plugin
  build = getword(blob:tmp, pos:0) +'\n';

  if (int(ver[2]) != int(build)) exit(1, "Unexpected build information.");

  # specific file info
  version += '.' + getword(blob:tmp, pos:2);

  set_kb_item(name:"ms_dns/version", value:version);

  if (report_verbosity > 0)
  {
    report = '\n  Reported version : ' + dns_version +
             '\n  Extended version : ' + version + 
             '\n';
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
  exit(0);
}
audit(AUDIT_NOT_LISTEN, "Microsoft DNS Server", port, "UDP");
