#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29923);
  script_version("$Revision: 1.8 $");

  script_name(english:"Avocent KVM Over IP Switch Detection");
  script_summary(english:"Looks for kvm.cgi and voice service");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a KVM switch." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Avocent KVM over IP switch that provides for
control of connected servers and devices." );
 # https://www.vertivco.com/en-us/products-catalog/monitoring-control-and-management/it-management/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76c8ca88" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this device if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/10");
 script_cvs_date("$Date: 2017/05/02 23:36:52 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8192);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("byte_func.inc");

# Test possible web servers.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:80);
ports = add_port_in_list(list:ports, port:443);

found = FALSE;
foreach port (ports)
{
  r = http_send_recv3(method:"GET",item:"/cgi-bin/kvm.cgi?&file=login", port:port);
  if (isnull(r)) continue;
  res = strcat(r[0], r[1], '\r\n', r[2]);
    if (
      (
        "<title>Avocent " >< res && 
        'href="http://support.avocent.com/"' >< res &&
        "Appliance firmware version " >< res
      ) ||
      (
        "Server: Avocent " >< res && 
        "Location: /dsview" >< res
      )
    )
    {
      set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

      # Collect some interesting info if this is the first web server found.
      if (!found)
      {
        info = "";

        if ("<title>Avocent " >< res)
        {
          model = strstr(res, "<title>Avocent ") - "<title>Avocent ";
          model = model - strstr(model, "</title");
          if (model)
          {
            info += '  Model : ' + model + '\n';
            set_kb_item(name:"Avocent/KVM/Model", value:model);
          }
        }

        firmware = NULL;
        if ("Appliance firmware version " >< res)
        {
          firmware = strstr(res, "Appliance firmware version ") - "Appliance firmware version ";
          if ("</" >< firmware) firmware = firmware - strstr(firmware, "</");
        }
        else
        {
          server = strstr(res, "Server:");
          server = server - strstr(server, '\r\n');

          firmware = strstr(server, "/") - "/";
        }
        if (!isnull(firmware) && firmware =~ "^[0-9]+[0-9.]+$")
        {
          info += '  Firmware version : ' + firmware + '\n';
          set_kb_item(name:"Avocent/KVM/Firmware", value:firmware);
        }

        if (info)
        {
          report = string(
            "\n",
            "Nessus was able to learn the following information about the remote\n",
            "device :\n",
            "\n",
            info
          );
          security_note(port:port, extra:report);
        }

        found = TRUE;
      }

  }
}
if (found)
{
  security_note(port:0);
  exit(0);
}


# Test video port.
port = 8192;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (soc)
{
  req = raw_string(
    0x53, 0x8d, 0xe0, 0xdd, 0xf2, 0x01, 0x19, 0x2f, 
    0x5d, 0x1f, 0xab, 0x14, 0x6c, 0x7d, 0x0f, 0x55, 
    0x83, 0x42, 0xaa, 0xe4, 0x0f, 0x7e, 0x17, 0xc4, 
    0x30, 0x24, 0x9c, 0x97, 0x71, 0xa4, 0xbd, 0xc6, 
    0xb2, 0x29, 0xef, 0x47, 0x27, 0x6c, 0x65, 0x0e, 
    0x79, 0x33, 0x07, 0x12, 0x0a, 0x6a, 0x81, 0xfa, 
    0x56, 0xdc, 0x78, 0x64, 0x75, 0x8e, 0xd6, 0xd2, 
    0xbc, 0xb8, 0x46, 0x32, 0x84, 0x61, 0xbc, 0x09, 
    0x02, 0x96, 0x2b, 0x3b, 0x55, 0x46, 0x5a, 0x79, 
    0x9f, 0xbd, 0xd1, 0x47, 0x4a, 0xbb, 0xed, 0xa9, 
    0x6c, 0x31, 0x13, 0x69, 0x45, 0x97, 0x01, 0x08, 
    0xe5, 0xed, 0x40, 0x3f, 0xeb, 0x4c, 0xb6, 0x30, 
    0x68, 0x27, 0x58, 0x2e, 0xe1, 0x23, 0xfc, 0x25, 
    0x73, 0x91, 0x4c, 0xa8, 0x11, 0x84, 0xd7
  );
  send(socket:soc, data:req);
  res = recv(socket:soc, length:64, min:16);
  close(soc);

  if (
    strlen(res) == 16 && 
    getbyte(blob:res, pos:5) == 0x84 &&
    getbyte(blob:res, pos:7) == 0x10
  )
  {
    security_note(port:0);
  }
}
