#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22227);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/04/20 21:37:48 $");

  script_name(english:"RMI Registry Detection");
  script_summary(english:"Detects an RMI registry.");

  script_set_attribute(attribute:"synopsis", value:
"An RMI registry is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an RMI registry, which acts as a bootstrap
naming service for registering and retrieving remote objects with
simple names in the Java Remote Method Invocation (RMI) system.");
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/javase/1.5.0/docs/guide/rmi/spec/rmiTOC.html");
  # http://docs.oracle.com/javase/1.5.0/docs/guide/rmi/spec/rmi-protocol3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb68319f");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1099);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("rmi.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(1099);
  if (!port) exit(0);
}
else port = 1099;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = rmi_connect(port:port);

# Discover the names bound to the registry.
host = this_host();
req2_1 =                             # client's default endpoint
  mkword(strlen(host)) + host +      #   hostname
  mkword(0) + mkword(0);             #   port
req2_2 =
  mkbyte(0x50) +                     # message (0x50 => CallData)
                                     # serialized object
    mkword(0xaced) +                 #   stream magic
    mkword(0x05) +                   #   stream version
    mkbyte(0x77) +                   #   blockdata
      mkbyte(0x22) +                 #     size
      raw_string(                    #     data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6,
        0x3b, 0xdf
      );
send(socket:soc, data:req2_1+req2_2);
res = recv(socket:soc, length:4096, min:5);
close(soc);

info = "";
# If it looks like a valid response...
if ("java.lang.String" >< res &&
  "java.rmi.NoSuchObjectException" >!< res)
{
  # Determine the number of names.
  data = strstr(res, "java.lang.String") - "java.lang.String";
  i = stridx(data, "t");
  if (i >= 0) n = getword(blob:data, pos:i-2);
  else n = 0;

  if (n > 0)
  {
    # Iterate over each name.
    j = i;
    for (i=0; i<n; i++)
    {
      if (data[j++] != 't') break;   # 't' => string.
      l = getword(blob:data, pos:j);
      if (l > 0 && l+j+2 <= strlen(data))
      {
        name = substr(data, j+2, j+2+l-1);
        j += l+2;
      }
      else break;

      # Get the remote reference for the name.
      soc = rmi_connect(port:port);
      req2_2 =
        mkbyte(0x50) +           # message (0x50 => CallData)
                                 # serialized object
        mkword(0xaced) +         #   stream magic
        mkword(0x05) +           #   stream version
        mkbyte(0x77) +           #   blockdata
          mkbyte(0x22) +         #     size
          raw_string(            #     data
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6,
            0x3b, 0xdf
          ) +
        mkbyte(0x74) +           #   string
          mkword(strlen(name)) + #   size
          name;                  #     data
      send(socket:soc, data:req2_1+req2_2);
      res = recv(socket:soc, length:4096, min:2);
      close(soc);

      # If ...
      if (
        # it's a return data and...
        getbyte(blob:res, pos:0) == 0x51 &&
        # it's a serialized object and...
        getword(blob:res, pos:1) == 0xaced &&
        # it's an RMI server and
        "java.rmi.server" >< res &&
        # it has a reference to the remote object
        "UnicastRef" >< res
      )
      {
        data2 = strstr(res, "UnicastRef") - "UnicastRef";
        # nb: adjust slightly if the object is of the UnicastRef2 type.
        if (data2[0] == "2") data2 = substr(data2, 2);
        l = getword(blob:data2, pos:0);
        if (l > 0 && (l+2-1+3 <= strlen(data2)))
        {
          ref_host = substr(data2, 2, l+2-1);
          ref_port = getword(blob:data2, pos:l+2-1+3);

          # nb: even when the host is 127.0.0.x, the service sometimes
          #     listens on all interfaces.
          if (ref_host =~ "127.0.0.[0-9]+" ||
            ref_host == "0.0.0.0" || ref_host == get_host_ip())
          {
            register_service(ipproto:"tcp", proto:"rmi_remote_object", port:ref_port);
            set_kb_item(name:"Services/rmi/" + ref_port + "/name", value:name);
            set_kb_item(name:"Services/rmi/" + ref_port + "/ref", value:hexstr(substr(res, 5)));
          }

          info += "  rmi://" + ref_host + ":" + ref_port + "/" + name + '\n';
        }
        else break;
      }
    }
  }
}

register_service(ipproto:"tcp", proto:"rmi_registry", port:port);

report = "";
if (len(info) > 0)
{
  report = '\nHere is a list of objects the remote RMI registry is currently\n' +
      'aware of :\n\n' + info;
}

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
