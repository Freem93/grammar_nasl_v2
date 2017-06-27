#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29929);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/10/16 22:09:59 $");

  script_name(english:"netOctopus Agent Detection (TCP)");
  script_summary(english:"Searches for an agent via TCP");

  script_set_attribute(attribute:"synopsis", value:
"An asset management agent is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a netOctopus Agent, the agent piece of the
netOctopus asset management software suite installed on individual
computers.");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:motorola:netoctopus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1917);

  exit(0);
}



include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(1917);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 1917;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Search for the agent.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

cmd = mkword(0x8f);
admin_serial = raw_string(0x01, 0x23, 0x45, 0x67);         # admin console's serial number

req = 
  mkword(0) + mkword(0) +
  mkword(0) + mkword(0) +
  mkword(0) + mkword(0) +
  mkword(0x8000) + mkword(0) +
  cmd + mkword(0) +
  mkword(4) + mkword(0) + 
  mkword(2) + mkword(0) + 
  admin_serial +
  mkword(0xffff);
send(socket:soc, data:req);
res1 = recv(socket:soc, length:64);


# If it looks right...
if (strlen(res1) == 64 && getbyte(blob:res1, pos:0) != 0)
{
  # Read the second packet.
  res2_1 = recv(socket:soc, length:14);
  if (getword(blob:res2_1, pos:0) == 0x8f && strlen(res2_1) == 14)
  {
    len = getdword(blob:res2_1, pos:2);
    res2_2 = recv(socket:soc, length:len);
    if (len == strlen(res2_2))
    {
      res2 = res2_1 + res2_2;

      octs = split(get_host_ip(), sep:'.', keep:FALSE);
      ip = raw_string(int(octs[0]), int(octs[1]), int(octs[2]), int(octs[3]));

      # If...
      if (
        substr(res2, 0x1a, 0x1d) == ip &&
        getword(blob:res2, pos:0x1e) == port &&
        substr(res2, strlen(res2)-2) == mkword(0xffff)
      )
      {
        # Extract some interesting info.
        info = "";
        # - version.
        ver = getbyte(blob:res1, pos:0x00) + '.' +
              (getbyte(blob:res1, pos:0x01) >> 4) + '.' +
              (getbyte(blob:res1, pos:0x01) & 0x0f);
        info += '  netOctopus Agent Version       : ' + ver + '\n';
        # - serial number.
        serial = hexstr(substr(res1, 0x04, 0x07)) + '-' +
                 hexstr(substr(res1, 0x08, 0x09)) + '-' +
                 hexstr(substr(res1, 0x0a, 0x0b)) + '-' +
                 hexstr(substr(res1, 0x0c, 0x0d)) + '-' +
                 hexstr(substr(res1, 0x0e, 0x13));
        serial = toupper(serial);
        info += '  netOctopus Agent Serial Number : ' + serial + '\n';
        count = getbyte(blob:res2, pos:0x59);
        if (count)
        {
          info += '  Administrator UUID(s)          : ';

          for (i=0; i<count; i++)
          {
            ofs = 0x5a + (i*16);
            pwuuid = hexstr(substr(res2, ofs+0,  ofs+3)) + '-' +
                     hexstr(substr(res2, ofs+4,  ofs+5)) + '-' +
                     hexstr(substr(res2, ofs+6,  ofs+7)) + '-' +
                     hexstr(substr(res2, ofs+8,  ofs+9)) + '-' +
                     hexstr(substr(res2, ofs+10, ofs+15));
            pwuuid = toupper(pwuuid);
            if (i == 0) info += pwuuid + '\n';
            else info += '                                   ' + pwuuid + '\n';
          }
        }

        # Register and report the service.
        register_service(port:port, ipproto:"tcp", proto:"netoctopus_agent");

        set_kb_item(name:"netOctopus/Agent/tcp/"+port+"/Version", value:ver);

        if (report_verbosity)
        {
          report = string(
            "\n",
            "Here is some information about the remote netOctopus Agent :\n",
            "\n",
            info
          );
          security_note(port:port, extra:report);
        }
        else security_note(port);
      }
    }
  }
}
