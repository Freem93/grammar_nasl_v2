#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58147);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/02/28 16:20:22 $");

  script_name(english:"BJNP Detection");
  script_summary(english:"Sends a discovery request");

  script_set_attribute(
    attribute:"synopsis", 
    value:"A printing service is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service supports BJNP, a proprietary USB over IP network 
printing protocol from Canon."
  );
  script_set_attribute(attribute:"solution", 
    value:"Limit access to this port if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


foreach port (make_list(8611, 8612))
{
  set_kb_item(name:"/tmp/bjnp/port", value:port);
}


port = get_kb_item("/tmp/bjnp/port");
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");


soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");


set_byte_order(BYTE_ORDER_BIG_ENDIAN);

code = 1;                              # 1 => discover
id = 0;                                # ?
seq = 1;                               # sequence number
if (port == 8611) type = 1;            # 1 => printer
else if (port == 8612) type = 2;       # 2 => scanner
else exit(1, "Don't know device type for UDP port "+port+".\n");

labels = make_array();
labels['CLS'] = 'Service type';
labels['CMD'] = 'Commands';
labels['DES'] = 'Printer name';
labels['MDL'] = 'Model';
labels['MFR'] = 'Manufacturer';
labels['VER'] = 'Firmware version';


payload = "";
req = 
  "BJNP" +
  mkbyte(type) +
  mkbyte(code) +
  mkdword(seq) +
  mkword(id) +
  mkdword(strlen(payload));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
if (strlen(res) == 0) exit(0, "The service on UDP port "+port+" failed to respond.");

# If it looks like a valid response...
if (
  strlen(res) >= 16 &&
  substr(res, 0, 3) == "BJNP" &&
  getbyte(blob:res, pos:4) == type | 0x80 &&
  getbyte(blob:res, pos:5) == code &&
  getdword(blob:res, pos:6) == seq &&
  getdword(blob:res, pos:12) + 16 == strlen(res)
)
{
  register_service(port:port, ipproto:"udp", proto:"bjnp");

  # Attempt to identify the printer / scanner.
  if (report_verbosity > 0)
  {
    report = "";

    code = 0x30;                       # get id.
    seq++;

    req2 = 
      "BJNP" +
      mkbyte(type) +
      mkbyte(code) +
      mkdword(seq) +
      mkword(id) +
      mkdword(strlen(payload));
    send(socket:soc, data:req2);
    res2 = recv(socket:soc, length:1024);
    if (
      strlen(res2) >= 16 &&
      substr(res2, 0, 3) == "BJNP" &&
      getbyte(blob:res2, pos:4) == type | 0x80 &&
      getbyte(blob:res2, pos:5) == code &&
      getdword(blob:res2, pos:6) == seq &&
      getdword(blob:res2, pos:12) + 16 == strlen(res2) &&
      "MFG:" >< res2 && 
      "MDL:" >< res2
    )
    {
      data = make_array();
      foreach datum (split(substr(res2, 18), sep:";"))
      {
        match = eregmatch(pattern:"^([^:]+):(.+);$", string:datum);
        if (match)
        {
          key = match[1];
          val = match[2];
          if (key == 'CLS')
          {
            if (val == 'PRINTER') val = 'Printer';
            else if (val == 'IMAGE') val = 'Scanner';
          }
          data[key] = val;

          if (key == 'VER') set_kb_item(name:"bjnp/"+port+"/version", value:val);
        }
      }

      max_label_len = 0;
      foreach key (keys(data))
      {
        if (labels[key])
        {
          label = labels[key];
          if (strlen(label) > max_label_len) max_label_len = strlen(label);
        }
      }

      foreach key (sort(keys(data)))
      {
        if (labels[key])
        {
          label = labels[key];
          report += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + data[key] + '\n';
        }
      }
    }

    # Register and report the service.
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
  close(soc);
  exit(0);
}
else 
{
  close(soc);
  exit(0, "The response from the service listening on port "+port+" does not look like it's from a BJNP service.");
}
