#
# (C) Tenable Network Security, Inc.
#

# RFC 1247 / RFC 2328 (OSPF v2)
# The OSPF protocol runs directly over IP, using IP protocol 89.
# Routing protocol packets should always be sent with the IP TOS field set
# to 0.
#
# Table 8: OSPF packet types.
#    1      Hello                  Discover/maintain  neighbors             
#    2      Database Description   Summarize database contents              
#    3      Link State Request     Database download                        
#    4      Link State Update      Database update                          
#    5      Link State Ack         Flooding acknowledgment
#


include("compat.inc");

if(description)
{
  script_id(11906);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Open Shortest Path First (OSPF) Agent Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an OSPF (Open Shortest Path First) agent." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OSPF, a popular routing protocol." );
 script_set_attribute(attribute:"solution", value:
"If the remote service is not used, disable it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Listen to OSPF packets");
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

##include("dump.inc");

include('global_settings.inc');

if ( ! thorough_tests)
 exit(0, 'The "Perform thorough tests" setting is not set.');

if ( islocalhost() ) exit(0);
if ( ! islocalnet() ) exit(0);

if (! defined_func("join_multicast_group")) exit(0);

join_multicast_group("224.0.0.5");	# AllSPFRouters
join_multicast_group("224.0.0.6");	# AllDRouters
# join_multicast_group is necessary, because pcap_next does not put the 
# interface in promiscuous mode

function clean_exit()
{
  leave_multicast_group("224.0.0.5");
  leave_multicast_group("224.0.0.6");
  exit(0);
}

function extract_ip_addr(pkt, off)
{
  # This avoids a dirty warning, but there is definitely a problem somewhere
  # Why do I receive short OSPF Hello packets?
  if (off + 4 > strlen(pkt))
    return '0.0.0.0';

  return
	strcat(	ord(pkt[off+0]), ".", 
		ord(pkt[off+1]), ".", 
		ord(pkt[off+2]), ".", 
		ord(pkt[off+3]));
}

f = "ip proto 89 and src " + get_host_ip();
p = pcap_next(pcap_filter: f, timeout: 5);
if (isnull(p)) clean_exit();

##dump(ddata: p, dtitle: "IP");

hl = ord(p[0]) & 0xF; hl *= 4;
ospf = substr(p, hl);

##dump(ddata: ospf, dtitle: "OSPF");

head = substr(ospf, 0, 24);
data = substr(ospf, 24);

# OSPF header
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   Version #   |     Type      |         Packet length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Router ID                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           Area ID                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Checksum            |             AuType            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

ver = ord(head[0]);
type = ord(head[1]);
len = ord(head[2]) * 256 + ord(head[3]);
rep = strcat('\nAn OSPF v', ver, ' agent is running on this host.\n');


# OSPF Hello packet
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Network Mask                           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         HelloInterval         |    Options    |    Rtr Pri    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                     RouterDeadInterval                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Designated Router                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                   Backup Designated Router                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Neighbor                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

if (type == 1)
{
  mask = extract_ip_addr(pkt: data, off: 0);
  rep += strcat('The netmask is ', mask, '\n');
  dr = extract_ip_addr(pkt: data, off: 12);
  if (dr != '0.0.0.0')
    rep += strcat('The Designated Router is ', dr, '\n');
  bdr = extract_ip_addr(pkt: data, off: 16);
  if (bdr != '0.0.0.0')
    rep += strcat('The Backup Designated Router is ', dr, '\n');
  n = extract_ip_addr(pkt: data, off: 20);
  if (n != '0.0.0.0')
    rep += strcat('Neighbor ', n, ' has been seen\n');
}

security_note(port: 0, protocol: "ospf", extra: rep);
clean_exit();
