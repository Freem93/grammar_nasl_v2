#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59713);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/02 17:53:33 $");

  script_name(english:"Active Inbound Connection From Host Listed in Known Bot Database");
  script_summary(english:"Uses results of nbin to report inbound botnet connections");

  script_set_attribute(
    attribute:"synopsis",
    value:
"According to a third-party database, the remote host is receiving an
inbound connection from a host that is listed as part of a botnet."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the output from netstat, the remote host has an inbound
connection from one or more hosts that are listed in a public database
as part of a botnet."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Determine which services the botnet hosts are connected to, and
investigate further if necessary."
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/06/26");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ipthreat_lookup_netstat.nbin");
  script_require_keys("botnet_traffic/inbound/report");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

report = get_kb_item_or_exit('botnet_traffic/inbound/report');
security_note(port:0, extra:report);
