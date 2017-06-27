#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(50677);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2017/01/05 15:38:09 $");

 script_name(english:"BitTorrent Mainline DHT Detection");
 script_summary(english:"DHT detection");

 script_set_attribute(attribute:"synopsis", value:
"A file-sharing service is running on the remote port." );
 script_set_attribute(attribute:"description", value:

"The remote host is participating in a Distributed Hash Table (DHT)
network, an indication of a peer-to-peer file-sharing application is
running on the host.  Specifically, this host is using Mainline DHT,
an implementation developed by the original BitTorrent client and
adopted by some others. 

Note that, due to the peer-to-peer nature of the application, any user
connecting to the P2P network may consume a large amount of
bandwidth."
);
 script_set_attribute(attribute:"see_also", value:"http://www.bittorrent.org/beps/bep_0005.html");
 script_set_attribute(attribute:"solution", value:
"Make sure that the use of this program agrees with your
organization's acceptable use and security policies. 

Note that filtering traffic to or from this port is not a sufficient
solution since the software can use a random port.");
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_require_keys("Services/udp/bittorrent");
 script_dependencies("bittorrent_detect.nasl");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


function send_data(port,data,udp)
{
  local_var soc,res;
  
  if(udp == 1)
    soc = open_sock_udp(port);
  else
    soc = open_sock_tcp(port);
    
  if ( ! soc ) return NULL;
   
  send(socket:soc, data:data);

  res = recv(socket:soc,length:4096);
  close(soc);
  
  return res;
}

function udp_sendrecv(port,data)
{
  return send_data(port:port,data:data,udp:1);
}


#
# try to get a DHT(Mainline) node id from remote host
# return:
#        NULL    -  if port not open or remote host 
#                   not responding to DHT 'ping' query
#       node_id  -  if a dht-capable bittorrent client
#                   is running on the port  
#
function dht_get_node_id(port)
{
  local_var  ping,res, pat,pos,node_id;
  
  node_id = NULL;
  
  # send DHT ping
  ping = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"; 
  res = udp_sendrecv(port:port,data:ping);
 
  # no response, it's not a bittorrent dht-capable client
  if (isnull(res)) return NULL;
 
  # 
  # ping response
  #
  #0x00:  64 31 3A 72 64 32 3A 69 64 32 30 3A 37 6E 7D 69    d1:rd2:id20:7n}i
  #0x10:  FA 4D DD E2 8C 86 22 84 EF 6F 25 45 BB 73 38 2D    .M...."..o%E.s8-
  #0x20:  65 31 3A 74 32 3A 61 61 31 3A 76 34 3A 55 54 57    e1:t2:aa1:v4:UTW
  #0x30:  E6 31 3A 79 31 3A 72 65                            .1:y1:re
  pat = "d1:rd2:id20:"; 
  if(preg(string:res, pattern:"^" + pat + ".{20}e1:t2:aa.*1:y1:re$",multiline: TRUE))
  {
    pos = strlen(pat);
    node_id = substr(res, pos, pos + 20 -1); 
  }
      
  return node_id;
}

#
# return a list of nodes, containing id,ip,and port
#
function dht_find_nodes(port, target)
{
  local_var find_node, res, i, j,num_nodes, nodes,pat, pat6;
  local_var nodes_data, nodes_length, node, node_size,ip_size;
  local_var pos,node_id_size;
  
  find_node = "d1:ad2:id20:abcdefghij01234567896:target20:" + target + "e1:q9:find_node1:t2:aa1:y1:qe";
  
  res = udp_sendrecv(port:port,data:find_node);
 
  if (isnull(res)) return NULL;

  # 
  # nodes returned
  #  
  #0x0000:  64 31 3A 72 64 32 3A 69 64 32 30 3A 37 6E 7D 69    d1:rd2:id20:7n}i
  #0x0010:  FA 4D DD E2 8C 86 22 84 EF 6F 25 45 BB 73 38 2D    .M...."..o%E.s8-
  #0x0020:  35 3A 6E 6F 64 65 73 32 30 38 3A 37 6E 7D 93 3C    5:nodes208:7n}.<
  #0x0030:  97 43 FE B6 C2 E4 E4 EE AF 57 E9 4C E1 2E 17 7B    .C.......W.L...{
  #0x0040:  92 08 C5 41 F1 37 6E 7E 6E E4 C5 41 37 81 F1 EF    ...A.7n~n..A7...
  #0x0050:  25 96 A4 54 87 4C 1F CD 82 BB 78 DA A8 30 5D 37    %..T.L....x..0]7
  #0x0060:  6E EF E7 3F 81 02 A6 AA 34 1C 45 00 0C 44 70 E9    n..?....4.E..Dp.
  #0x0070:  1A 27 1E 59 93 5E 8C A4 52 37 6E EB 1B 47 12 FE    .'.Y.^..R7n..G..
  #0x0080:  27 B3 AE 64 6B 69 CE 56 BE 9D 81 82 F3 4D A0 F1    '..dki.V.....M..
  #0x0090:  EC 7E A4 37 6E E5 EB F1 77 3A 6B 11 89 1C 27 42    .~.7n...w:k...'B
  #0x00A0:  DB EF E3 7F 53 12 CD 4D 17 61 C6 B9 12 37 6E E6    ....S..M.a...7n.
  #0x00B0:  37 E0 AB 12 D3 8F F6 12 C9 02 C6 B0 4E D5 58 55    7...........N.XU
  #0x00C0:  DF 5F 3A A6 65 6E 0E 37 6E DC 5E 35 E6 4D 59 64    ._:.en.7n.^5.MYd
  #0x00D0:  B6 EC 1E 30 18 D7 E0 79 7B BC 2B 4D 5B C1 DB 2A    ...0...y{.+M[..*
  #0x00E0:  99 37 6E 93 42 09 89 D2 7D AF 3E EB B2 99 F3 F0    .7n.B...}.>.....
  #0x00F0:  F0 3F C6 50 13 47 7F 7D 16 1B 57 65 31 3A 74 32    .?.P.G.}..We1:t2
  #0x0100:  3A 61 61 31 3A 76 34 3A 55 54 57 E6 31 3A 79 31    :aa1:v4:UTW.1:y1
  #0x0110:  3A 72 65                                           :re
  
  pat  = "d1:rd2:id20:" + target + "5:nodes";
  pat6 = "d1:rd2:id20:" + target + "6:nodes6";
  if(strstr(res,pat))
  {
    nodes_data = substr(res, strlen(pat), strlen(res) -1); 
    ip_size = 4;
  }
  else if(strstr(res,pat6))
  {
    nodes_data = substr(res, strlen(pat6), strlen(res) -1); 
    ip_size = 16;
  }
  else
    return NULL;
  
  # get nodes length
  i = 0;
  for (i = 0 ; i < strlen(nodes_data); i++)
  {
    if(nodes_data[i] == ":")
      break;
      
    nodes_length += nodes_data[i];
  }
  
  if(i == strlen(nodes_data)) return NULL;
    
  if(nodes_length =~ "[^0-9]") return NULL;
  
  nodes_length = uint(nodes_length);
  if(nodes_length > strlen(nodes_data)) return NULL;
  
  i++; # skip ":"
  nodes_data = substr(nodes_data, i, i + nodes_length);
  
  node_id_size = 20;  
  node_size = node_id_size + ip_size + 2; # 2-byte port
  
  if(nodes_length % node_size) return NULL;
  
  num_nodes = nodes_length / node_size;
  
  j = 0;
  for(i = 0; i < num_nodes;i++)
  {
    pos = j;
    node['id']   = substr(nodes_data, pos, pos + node_id_size - 1);
    pos = j + node_id_size;
    node['ip']   = substr(nodes_data, pos, pos + ip_size -1);
    pos = j + node_id_size + ip_size;
    node['port'] = substr(nodes_data, pos, pos + 1);
    nodes[i] = node; 
    j += node_size;    
  }
  
  return nodes;
}

function ipv4_str(ip)
{
  if(strlen(ip) < 4) return NULL;
  
  return string(ord(ip[0]), ".", ord(ip[1]), ".", ord(ip[2]), ".", ord(ip[3]));     
}

function ipv6_str(ip)
{
  local_var i, str;
  
  if(strlen(ip) < 16) return NULL;
  for (i = 0; i < 16; i++)
  {
    str += hexstr(ip[i]);
    if( (i % 2) && i != 15)
      str += ":";
  }
  
  return str;
}

function port_str(port)
{
  return string((ord(port[0]) << 8) + ord(port[1]));
}


# convert node list to string
function nodes_str(nodes)
{
  local_var node, nodes_str, port;
  
  foreach node (nodes)
  {
    port = node['port'];
    # skip scanner's IP
    if(node['ip'] != this_host_raw())
    {
      if(strlen(node['ip']) == 4)
        nodes_str += ipv4_str(ip: node['ip']) + "/" + port_str(port:port) + '\n';
      else if (strlen(node['ip']) == 16)
        nodes_str += ipv6_str(ip:node['ip']) + "/" +  port_str(port:port) + '\n';
    }
  }
  
   return nodes_str;
}

port_list = make_list();

bt_ports = get_kb_list("Services/udp/bittorrent");
if(!isnull(bt_ports)) 
  port_list = make_list(port_list, bt_ports);
  
unknown_ports = get_kb_list("Services/unknown");
if(!isnull(unknown_ports))
  port_list = make_list(port_list, unknown_ports);

foreach port (port_list)
{
  # skip closed UDP ports
  if (!get_udp_port_state(port))
    continue;
      
  node_id = dht_get_node_id(port:port);
  if(node_id)
  {
    if (report_verbosity > 0)
    {
      report = '\nnode_id : ' + hexstr(node_id) + '\n';
      good_nodes = dht_find_nodes(port:port, target: node_id);
      if (good_nodes) info = nodes_str(nodes:good_nodes);
      if(info)
        report += 'good nodes in the routing table:\n' + info;
   
      security_note(port:port, protocol:'udp', extra:report);
    }
    else security_note(port:port, protocol:'udp');
    if(service_is_unknown(port:port, ipproto:"udp"))
      register_service(port:port, ipproto:"udp", proto:"mainline-dht");
  }
}
