#TRUSTED 30918f94d4a3a8419aa41f707136c53e50f655b8f03c364486357320757d4dd030f7c41fcced58096f47979f22aac4801d0cc785edace5a29f629c35bac701eb9a1bc77de7bcb56f83ec2ccda848990b946c209593a5bc21678ee82f010b137f7b1d800da5080a7170f60eccec8c0d0040eee95a5d1be9cddf673727cb4bb58225dd25b62ade9a54ef7125170347d54dd4516d81b96422f85d65c3ebe24c7755fb82af0882e9a786baad4e4c5179be5cf36ccb624828c61eb88d2e9f342f94f900b74b2b9350ff7d6b7b2a2491353a5f680456fdc2e401f5ae04a4ef71978d8f3b89c0948856d14b4a463f72e389c7cef144581bf721e0161c2dfdf66b13ed81eeead10d8e5813ce3bfa16f0b60e6400ad17f400b2716668bde0868261a82afcea2fc3c3af6489024c4ff80153e0ef6cb7d5a1d6e46ff93f5c4f5beb0154a7f0bcafed22a6773404493efd6bae6a7fbff53731b03231956d6ba1c8aa4241f2ee24f7c6b66b13acd67aa91761d280e4338e559a858474049c0ba7374710504a6ecbdd0986ef5c177949d0512c0ddd3723b879e9ac6299e13b70c33df4c7622a40b875aa396396622d6e538903841d3d06e682fc9cbe3558571d5f9ce3eaf80df90b5eaf45896700460eb7620aa2efb7e22818b0870fac459efc9764e7dade82efe430f54e985470433529694c0113706a25f76e0691cb6f485de479886268904d
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# v1.5


#
# UDP
#


# Define a UDP structure
udp_sizes = make_array(
		"uh_sport", 16,
		"uh_dport", 16,
		"uh_ulen",  16,
		"uh_sum",   16);

udp_struct = make_list(
		"uh_sport",
		"uh_dport",
		"uh_ulen",
		"uh_sum");


function udp_checksum(udp, ip, payload)
{
 local_var src, dst, pseudo, udp_r, ret;
 local_var padding;

 if ( ip["type"] != "ip" || udp["type"] != "udp" )
	{
	display("udp_checksum: Bad IP argument\n");
	return NULL;
	}
 ip  = ip["data"];

 
 udp_r = mkudp(udp);
 
 src = ipaddr(ip["ip_src"]);
 dst = ipaddr(ip["ip_dst"]);
 if ( strlen(payload) & 1 == 1 ) padding = raw_string(0);
 else padding = NULL;

 pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_UDP) +
	  mkword(strlen(udp_r) + strlen(payload)) + udp_r + payload + padding;

 ret = inet_sum(pseudo);
 return ret;
}

function udp_get(udp, element)
{
 if ( isnull(udp) || udp["type"] != "udp" )
	{
	display("udp_get: Invalid packet\n");
	return NULL;
	}

 udp = udp["data"];
 return udp[element];
}

function udp_set(udp, uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var ret;
 if ( isnull(udp) || udp["type"] != "udp" )
 {
  display("udp_set: Bad packet type\n");
  return NULL;
 }

 udp = udp["data"];
 if ( !isnull(uh_sport) ) udp["uh_sport"] = uh_sport;
 if ( !isnull(uh_dport) ) udp["uh_dport"] = uh_dport;
 if ( !isnull(uh_ulen) ) udp["uh_ulen"] = uh_ulen;
 if ( !isnull(uh_sum) ) udp["uh_sum"] = uh_sum;


 ret["type"] = "udp";
 ret["data"] = udp;
 return ret;
}


function mkudp()
{
 local_var item, ret, n, b, udp;

 udp = _FCT_ANON_ARGS[0];
 
 if ( udp["type"] != "udp") 
 {
   display("mkudp : Bad packet type - ", udp["type"], "\n");
 } 

 udp = udp["data"];

 foreach item ( udp_struct )
 {
     if ( udp_sizes[item] == 16 ) ret += mkword(udp[item]);
     else {
	display("Inconsistent UDP structure\n");
	return NULL;
	}
 }

 return ret;
}


function udp(uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var empty;
 if ( isnull(uh_sport) ) uh_sport = 1024;
 if ( isnull(uh_dport) ) uh_dport = 53;
 if ( isnull(uh_ulen ) ) uh_ulen  = 8;
 if ( isnull(uh_sum  ) ) uh_sum   = 0;

 empty["type"] = "udp";
 empty["data"] = NULL;
 return udp_set(udp:empty,
		uh_sport:uh_sport,
		uh_dport:uh_dport,
		uh_ulen: uh_ulen,
		uh_sum : uh_sum);
}

global_var _udp_buf;

##
# Get a single line of text from a UDP socket.
#
# @param length  Maximum number of bytes to receive, passed to recv
# @param socket  UDP socket to read from
# @param timeout Number of seconds to wait for data, passed to recv
#
# @remark This function cannot be used across multiple sockets at the
#         same time, as the buffer is global.
#
# @return A single line of text from the UDP socket.
##
function udp_recv_line(length, socket, timeout)
{
  local_var data, i, line;

  # Sanity check parameters.
  if (isnull(length))
    return NULL;

  if (isnull(socket))
    return NULL;

  # Make sure that there's a line in the buffer.
  while (TRUE)
  {
    # Check if we have a line yet.
    i = stridx(_udp_buf, '\n');
    if (i != -1)
      break;

    # Get new data from the socket.
    data = recv(socket:socket, length:length, timeout:timeout);
    if (isnull(data))
      return NULL;

    _udp_buf += data;
  }

  # Cut a line out of the buffer.
  line = substr(_udp_buf, 0, i);
  _udp_buf = substr(_udp_buf, i + 1);

  return line;
}

##
# Clears the UDP buffer used by [udp_recv_line].
##
function udp_recv_line_reset()
{
  _udp_buf = "";
}
