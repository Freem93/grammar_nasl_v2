#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64582);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/05 16:10:34 $");

  script_name(english:"Netstat Connection Information");
  script_summary(english:"Attempts to parse results of 'netstat' command.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to parse the results of the 'netstat' command on the
remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has listening ports or established connections that
Nessus was able to extract from the results of the 'netstat' command.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("netstat_portscan.nasl", "wmi_netstat.nbin");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');
include('agent.inc');

report = "";

netstat = get_kb_item('Host/netstat');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/netstat_ano');
if (isnull(netstat))
  netstat = get_kb_item('Host/Windows/netstat_an');
if (isnull(netstat))
  exit(0, 'No netstat output was found in the KB.');

lines = split(netstat);

global_var ip_port_match_pattern;
# 10 groups
ip_port_match_pattern =
"(" +
  "(" +
    "(\[[a-f0-9:]+\]|[0-9a-f]*:[0-9a-f:]+)" + # ipv6 address
    "|" +
    "(\[[a-f0-9:]+%[0-9a-z]+\]|[0-9a-f]*:[0-9a-f:]+%[0-9a-z]+)" + # ipv6 address w/ zone index
    "|" +
    "(([0-9a-f]*:[0-9a-f:]+:)" + # possible embedded ipv6 address with ipv4
    "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))" +
    "|" +
    "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" + # ipv4
    "|\*" +
  ")" +
  "[:.]([0-9]+|\*)" + # port
  "[ \t]+" + # end anchor
")";

function parse_host(host)
{
  local_var item, ip_ver;
  item = eregmatch(string:host, pattern: ip_port_match_pattern);
  if(!isnull(item[9]) && !isnull(item[2]))
  {
    ip_ver = '';

    if(item[3] == item[2])
      ip_ver = '6';
    if(item[4] == item[2])
      ip_ver = '6';
    if(item[5] == item[2])
      ip_ver = '46';
    if(item[8] == item[2])
      ip_ver = '4';

    return make_array("host", item[2],
                      "port", item[9],
                      "ip_ver", ip_ver);
  }
  else
    return NULL;
}

lines = split(netstat, keep:FALSE);

cur_proto = '';
cur_proto_ip_ver = '';
i=0;
j=0;
ip_ver = '';

foreach line (lines)
{
  item = eregmatch(pattern: "^[ \t]*(UDP|TCP|udp|tcp)([46]{0,2})[ \t:]{1}", string:line);
  if(!isnull(item))
  {
    cur_proto_ip_ver = '';
    if("udp" >< tolower(item[1]))
      cur_proto = "udp";
    else cur_proto = "tcp";
    if("IPv4" >< line)
      cur_proto_ip_ver = '4';
    if("IPv6" >< line)
      cur_proto_ip_ver = '6';
  }

  if(cur_proto_ip_ver != '')
    ip_ver = cur_proto_ip_ver;

  if(ip_ver == '' && !isnull(item[2]))
    ip_ver = item[2];

  if(cur_proto == "tcp")
  {
    pattern = "(^|[ \t])" + ip_port_match_pattern + ip_port_match_pattern;
    item = eregmatch(pattern:pattern, string:line);
  }
  if(cur_proto == "udp")
  {
    pattern = "(^|[ \t])" + ip_port_match_pattern + ip_port_match_pattern;
    item = eregmatch(pattern:pattern, string:line);

    # to handle solaris
    pattern = "(^|[ \t])" + ip_port_match_pattern + "[Ii]dle($|[ \t]*$)";
    if(isnull(item))
      item = eregmatch(pattern:pattern, string:line);

  }
  if(isnull(item)) continue;

  # determine state - 'established' or 'listen'
  state = '';
  lower_line = tolower(line);
  if((cur_proto == 'udp' && 'idle' >< lower_line) ||
     (cur_proto == 'tcp' && 'listen' >< lower_line))
  {
    state = 'listen';
  }
  if(cur_proto == 'tcp' && 'established' >< lower_line)
    state = 'established';

  res_src = parse_host(host:item[2]);
  if(ip_ver == '')
    ip_ver = res_src["ip_ver"];
  else if(ip_ver != '46' && (ip_ver != res_src["ip_ver"]) && res_src["ip_ver"] != '')
    ip_ver = '46';

  res_dst = NULL;
  if(chomp(item[11]) != '' && !isnull(item[11]))
  {
    res_dst = parse_host(host:item[11]);
    if(ip_ver == '')
      ip_ver = res_dst["ip_ver"];
    else if(ip_ver != '46' && (ip_ver != res_dst["ip_ver"]) && res_dst["ip_ver"] != '')
      ip_ver = '46';
  }

  if(cur_proto == 'tcp')
  {
    src_wildcard = FALSE;
    dst_wildcard = FALSE;

    if((res_src["host"] == "*" || res_src["host"] == "0.0.0.0" ||
        res_src["host"] == "::" || res_src["host"] == "::0.0.0.0") &&
        res_src["port"] == "*")
      src_wildcard = TRUE;

    if((res_dst["host"] == "*" || res_dst["host"] == "0.0.0.0" ||
        res_dst["host"] == "::" || res_dst["host"] == "::0.0.0.0") &&
        (res_dst["port"] == "*" || res_dst["port"] == "0"))
      dst_wildcard = TRUE;

    if (state == '')
    {
      if (dst_wildcard)
        state = 'listen';
      else if (!src_wildcard && !dst_wildcard)
        state = 'established';
    }
  }
  if(cur_proto == 'udp')
  {
    src_wildcard = FALSE;
    dst_wildcard = FALSE;

    if((res_src["host"] == "*" || res_src["host"] == "0.0.0.0" ||
        res_src["host"] == "::" || res_src["host"] == "::0.0.0.0") &&
        res_src["port"] == "*")
      src_wildcard = TRUE;

    if((res_dst["host"] == "*" || res_dst["host"] == "0.0.0.0" ||
        res_dst["host"] == "::" || res_dst["host"] == "::0.0.0.0") &&
        res_dst["port"] == "*")
      dst_wildcard = TRUE;

    if(state == '')
    {
      if(src_wildcard || dst_wildcard)
        state = 'listen';
      else if(!src_wildcard && !dst_wildcard)
        state = 'established';
    }
  }

  # unhandled state
  if(state == '' ||
     (src_wildcard && dst_wildcard))
    continue;

  report += cur_proto + ip_ver;
  report += ' (' + state + ')\n';
  if(!isnull(res_src))
    report += "  src: [host=" + res_src["host"] + ', port=' + res_src["port"] + "]" + '\n';
  if(!isnull(res_dst))
    report += "  dst: [host=" + res_dst["host"] + ', port=' + res_dst["port"] + "]" + '\n';

  if(state == 'listen')
  {
    set_kb_item(name:'Netstat/listen-' + i + '/' + cur_proto + ip_ver, value: res_src["host"] + ':' + res_src["port"]);
    if(defined_func("report_xml_tag"))
    {
      report_xml_tag(tag:'netstat-listen-' + cur_proto + ip_ver + '-' + i,
                     value: res_src["host"] + ':' + res_src["port"]);
    }
    i++;
  }
  else if(state == 'established')
  {
    set_kb_item(name:'Netstat/established-' + j + '/' + cur_proto + ip_ver, value: res_src["host"] + ':' +
                res_src["port"] + '-' + res_dst["host"] + ':' + res_dst["port"]);
    if(defined_func("report_xml_tag"))
    {
      report_xml_tag(tag:'netstat-established-' + cur_proto + ip_ver + '-' + j,
                     value: res_src["host"] + ':' + res_src["port"] + '-' +
                            res_dst["host"] + ':' + res_dst["port"]);
    }
    j++;
  }
  report += '\n';
  ip_ver = '';
}

if (agent())
{
  agent_ip = agent_get_ip();
  if(!isnull(agent_ip))
    report_xml_tag(tag:"host-ip", value:agent_ip);
}

if (report != "")
{
  if(report_verbosity > 0)
    security_note(extra: report, port:0);
  else security_note(0);
  exit(0);
}
