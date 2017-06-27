#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34396);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/30 22:03:44 $");

  script_name(english:"ASG-Sentry SNMP Agent Detection");
  script_summary(english:"Sends an SNMP request");

 script_set_attribute(attribute:"synopsis", value:
"An SNMP agent is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote SNMP agent is part of ASG-Sentry, a web-based SNMP network
management system." );
 # http://web.archive.org/web/20081217021017/http://www.asg.com/products/product_details.asp?code=SNM&id=96
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0da8508b" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");


foreach port (make_list(6161, 8161))
{
  if (! service_is_unknown(port:port, ipproto:"udp")) continue;
  if (! get_udp_port_state(port)) continue;

  soc = open_sock_udp(port);
  if (!soc) continue;

  # Protect against the fact that this host may be configured for SNMPv3 auth.
  set_snmp_version( version:1 );

  # Look for evidence of ASG-Sentry
  community = "public";
  desc = snmp_request(
    socket:soc,
    community:community,
    oid:"1.3.6.1.2.1.1.1.0"
  );
  if (desc && "ASG-Sentry" >< desc)
  {
    register_service(port:port, ipproto:"udp", proto:"snmp");
    set_kb_item(name:"SNMP/"+port+"/ASG_Sentry/sysDesc", value:desc);

    if (report_verbosity)
    {
      info = '  sysDescr    : ' + desc + '\n';

      # Collect some additional info for a report.
      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.2.0"
      );
      if (res) info += '  sysObjectID : ' + res + '\n';

      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.3.0"
      );
      if (res) info += '  sysUptime   : ' + res + '\n';

      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.4.0"
      );
      if (res) info += '  sysContact  : ' + res + '\n';

      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.5.0"
      );
      if (res) info += '  sysName     : ' + res + '\n';

      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.6.0"
      );
      if (res) info += '  sysLocation : ' + res + '\n';

      res = snmp_request(
        socket:soc,
        community:community,
        oid:"1.3.6.1.2.1.1.7.0"
      );
      if (res) info += '  sysServices : ' + res + '\n';

      report = string(
        "\n",
        "Here is some information collected from the remote agent :\n",
        "\n",
        info
      );
      security_note(port:port, proto:"udp", extra:report);
    }
    else security_note(port:port, proto:"udp");
  }
  # We're done with actual sends, so set the SNMP_VERSION back, if needed.
  reset_snmp_version();
}
