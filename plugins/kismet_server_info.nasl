#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33257);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");

  script_name(english:"Kismet Server Information Disclosure");
  script_summary(english:"Gathers information from a Kismet Server");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to collect information from the remote wireless
monitoring service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Kismet server and allows clients to use
it to monitor wireless activity.  An anonymous attacker may use the
information collected to gain a better understanding of your network." );
 script_set_attribute(attribute:"see_also", value:"http://svn.kismetwireless.net/code/trunk/docs/DEVEL.client" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired and, if appropriate,
don't allow clients to list WEP keys." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/kismet_server", 2501);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/kismet_server");
if (!port) port = 2501;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Splits a line into fields delimited by spaces and handles
# "buffered" fields that could themselves contain spaces.
function split1(s)
{
  local_var fields, i, pat, repl;

  while (!repl || repl >< s)
    repl = rand_str(length:4);

  pat = '\x01([^\x01]*) ([^\x01]*)\x01';
  while (ereg(pattern:pat, string:s))
      s = ereg_replace(pattern:pat, replace:"\1"+repl+"\2", string:s);
  s = str_replace(find:'\x01', replace:'', string:s);

  fields = split(s, sep:" ", keep:FALSE);
  for (i=0; i<max_index(fields); i++)
    fields[i] = str_replace(find:repl, replace:" ", string:fields[i]);

  return fields;
}


# Read the banner.
res = recv(socket:soc, length:10240);
if (strlen(res) == 0) exit(0);
if (stridx(res, '*KISMET: ') != 0) exit(0);


# Collect various info.
if (report_verbosity)
{
  info = string(
    "Information about the remote Kismet server :\n",
    "\n"
  );

  lines = split(res, keep:FALSE);
  fields = split1(s:lines[0]);
  if (fields[2] =~ "^[0-9]{10,}$") 
  {
    server = fields[3];
    server = ereg_replace(pattern:"^\.(.+)\.$", replace:"\1", string:server);
    info += '  ' + 'Server name : ' + server + '\n\n';
  }

  if ("*PROTOCOLS: " >< res)
  {
    protocols = strstr(res, "*PROTOCOLS: ") - "*PROTOCOLS: ";
    protocols = protocols - strstr(protocols, '\n');
    protocols = str_replace(find:",", replace:", ", string:protocols);
    info += '  ' + 'Protocols   : ' + protocols + '\n\n';

    if (report_verbosity > 1)
    {
      req = '!0 REMOVE TIME\n';
      if (', CARD' >< protocols || 'CARD, ' >< protocols)
          req += '!0 ENABLE CARD interface,type\n';
      if (', CLIENT' >< protocols || 'CLIENT, ' >< protocols)
          req += '!0 ENABLE CLIENT bssid,mac\n';
      if (', NETWORK' >< protocols || 'NETWORK, ' >< protocols)
          req += '!0 ENABLE NETWORK bssid,ssid\n';
      if (', WEPKEY' >< protocols || 'WEPKEY, ' >< protocols)
          req += '!0 ENABLE WEPKEY bssid,key\n' +
                 '!0 LISTWEPKEYS\n';
      if (req)
      {
        send(socket:soc, data:req);
        res2 = recv(socket:soc, length:10240);

        if (strlen(res2))
        {
          info = string(
            info,
            "Information about wireless network infrastructure collected by\n",
            "the remote Kismet server :\n",
            "\n"
          );

          output = make_array();
          foreach line (split(res2, keep:FALSE))
          {
            if (line =~ "\*[A-Z]+: ")
            {
              label = ereg_replace(pattern:"^\*([A-Z]+): (.+)$", replace:"\1", string:line);
              data = ereg_replace(pattern:"^\*([A-Z]+): (.*)$", replace:"\2", string:line);

              if (strlen(output[label])) 
              {
                if (data >!< output[label]) output[label] += data + '\n';
              }
              else output[label] = data + '\n';
            }
          }

          foreach label (make_list("CARD", "NETWORK", "WEPKEY", "CLIENT"))
          {
            if (strlen(output[label]))
            {
              if ("CARD" == label) text = "Card";
              else if ("CLIENT" == label) text = "Client";
              else if ("NETWORK" == label) text = "Network";
              else if ("WEPKEY" == label) text = "WEP Key";
        
              n = 0;
              lines = split(output[label], keep:FALSE);
              foreach line (lines)
              {
                n++;
                if (max_index(lines) > 1)
                  info += '  ' + text + ' ' + n + '\n';
                else 
                  info += '  ' + text + '\n';

                fields = split1(s:line);
                if ("CARD" == label)
                {
                  info += '    Interface : ' + fields[0] + '\n' +
                          '    Type      : ' + fields[1] + '\n' +
                          '\n';
                }
                else if ("CLIENT" == label)
                {
                  info += '    BSSID     : ' + fields[0] + '\n' +
                          '    MAC       : ' + fields[1] + '\n' +
                          '\n';
                }
                else if ("NETWORK" == label)
                {
                  info += '    BSSID     : ' + fields[0] + '\n' +
                          '    SSID      : ' + fields[1] + '\n' +
                          '\n';
                }
                else if ("WEPKEY" == label)
                {
                  info += '    BSSID     : ' + fields[0] + '\n' +
                          '    Key       : ' + fields[1] + '\n' +
                          '\n';
                }
              }
            }
          }
        }
      }
    }
  }
}


# Report the findings.
if (report_verbosity)
{
  report = string(
    "\n",
    info
  );
  security_warning(port:port, extra:report);
}
else security_warning(port);
