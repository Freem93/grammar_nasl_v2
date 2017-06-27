#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66717);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/31 14:41:19 $");

  script_name(english:"mDNS Detection (Local Network)");
  script_summary(english:"mDNS detection on the local network");

  script_set_attribute(
    attribute:"synopsis",
    value:"It is possible to obtain information about the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote service understands the Bonjour (also known as ZeroConf or
mDNS) protocol, which allows anyone to uncover information from the
remote host such as its operating system type and exact version, its
hostname, and the list of services it is running. 

This plugin attempts to discover mDNS used by hosts residing on the same
network segment as Nessus."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Filter incoming traffic to UDP port 5353, if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mdns.nasl");
  script_require_keys("/tmp/mdns/report");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'mdns', ipproto:'udp', exit_on_fail:TRUE);
report = get_kb_item_or_exit('/tmp/mdns/' + port + '/report');

if (report_verbosity > 0)
  security_note(port:port, proto:"udp", extra:report);
else
  security_note(port:port, proto:"udp");

