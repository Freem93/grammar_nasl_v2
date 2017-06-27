#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44329);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/02/23 16:42:04 $");

  script_name(english:"X-format Communications Protocol (XCP) Detection");
  script_summary(english:"Sends a Standard ID Block request");

  script_set_attribute(
    attribute:"synopsis", 
    value:"A UPS monitoring service is listening on the remote port."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service supports the X-format Communications Protocol 
(XCP), commonly used to monitor Eaton-/Powerware-branded UPSes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5b90702"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit access to this port."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = 7010;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");


soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");


# This calculates a two's complement checksum as used by XCP.
function checksum(data)
{
  local_var i, n, sum;

  n = strlen(data);
  if (!n) return 0;

  sum = 0;
  for (i=0; i<n; i++)
    sum = sum + ord(data[i]);

  sum = (~sum + 1) & 0xFF;
  return sum;
}


# Send a Standard ID Block request.
req = mkbyte(0xab) +                        # magic
      mkbyte(1) +                           # number of commands
      mkbyte(0x31);                         # command (0x31 => Standard ID Block request)
req += mkbyte(checksum(data:req));          # checksum
send(socket:soc, data:req);


# Read header and check if it looks ok.
res_1 = recv(socket:soc, length:4, min:4);
if (
  strlen(res_1) == 4 &&
  getbyte(pos:0, blob:res_1) == 0xab &&     # magic
  getbyte(pos:1, blob:res_1) == 1 &&        # block number (1 => Standard id block)
  getbyte(pos:2, blob:res_1) > 0 &&         # length
  (getbyte(pos:3, blob:res_1) & 0x7f) == 1  # sequence number
)
{
  # If it does, read the rest of the packet.
  len = getbyte(pos:2, blob:res_1);
  res_2 = recv(socket:soc, length:len+1, min:len+1);
  res = res_1 + res_2;

  # If the length and checksum are correct...
  if (
    strlen(res_2) == len+1 &&
    checksum(data:res_1+substr(res_2, 0, len-1)) == getbyte(pos:len, blob:res_2)
  )
  {
    # Register and report the service.
    register_service(port:port, proto:"xcp");

    info = "";
    if (report_verbosity > 0)
    {
      # Collect descriptive message.
      va = getbyte(pos:3, blob:res_2);
      if (va)
      {
        va = string(va, 'K');
        desc_ofs = 6;
      }
      else 
      {
        va = getword(pos:4, blob:res_2) * 50;
        desc_ofs = 8;
      }

      desc_len = getbyte(pos:desc_ofs, blob:res_2);
      desc = substr(res_2, desc_ofs+1, desc_ofs+1+desc_len-1);
      if (ord(desc[desc_len-1]) == 0) desc = substr(desc, 0, desc_len-2);

      if (strlen(desc)) info += '  Description : ' + desc + '\n';
      if (va)           info += '  VA rating   : ' + va + '\n';
    }

    if (info)
    {
      report = '\n' +
        'Nessus collected the following information from the remote XCP\n' +
        'service :\n' +
        '\n' +
        info;
      security_note(port:port, proto:"udp", extra:report);
    }
    else security_note(port:port, proto:"udp");

    close(soc);
    exit(0);
  }
  else 
  {
    close(soc);
    exit(1, "Failed to read "+len+" bytes from the server on port "+port+".");
  }
}
else
{
  close(soc);
  exit(0, "The response from the service listening on port "+port+" does not agree with the XCP specification.");
}
