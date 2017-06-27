#TRUSTED 07ac2f26c9151e361a71b4c2f57cb10a5e2cc928f90c04092d985a55c28fa4dd1c80c70f0a29f4547f825f93a52cd06fcfb9bf3788e0456bae996932c96d363146d98316b010b88926f029fd322d8fb6fb7ae0ec805e9774f9a571affdd58c401ce1a588fbddd7a4e64e36fda72fc70fdf67bae16675b9c9930d0c400ec1af7dcc78e1b67dcf6de4f4e96aa1e8a9ef401029574d4fc430c5656799f951287060c1c73eaca7e67c2290b215d825dcc56249eb55156c109e839c1c7ba58d58c611782678b67f1787297861196c5005315404afcdda3b0c19ac4093a81b38d3bdb32698c3bf79cd7727220f49436848fa2a6c19627d2f68dd8a2d1fb91eaea6f2095c481bcc42a5a6283d5d9c4f3ef5e45c6ad3457039209622477a8ba2dce07e73911f3cfa52189dda4646fbf6040fe4ded6bbd67e87de66eb7df2c551496bba868223f67dd43f572913aa96cb3dd44ee5ff3836b0770981d88a68b4317132b6638a0d1d16063052507445fd646625d64107b26ef3345d72449505d73d14cb2aa2f9485607b1b4db17722e6add15a522d643d2091c60724577ae9b242a3079618749347453a1c9a7dbeee280ece2e850a193110901abae7f31130abbcbda0d67beeeebfff69eee8b7abc45caed7950a22caeb2310be8ce8ffa08215fd31f4dd0f31facdd85d340416f3cf8fcca563c70a68e46a40b993dc7df608c3e72929ad32d
#
# This NASL script was written by Martin O'Neal of Corsaire 
# (http://www.corsaire.com)
# 
# The script provides basic tftp functionality for use in other scripts...
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# GPLv2
# 
# Some code was added by Michel Arboi <mikhail@nessus.org>
# Also Ron Bowes <rbowes@tenable.com> cleaned up the code in tftp_get and
# tftp_put and added support for an optional 'data' parameter in the later.
#
# v1.2

TFTP_RRQ        = 1;
TFTP_WRQ        = 2;
TFTP_DATA       = 3;
TFTP_ACK        = 4;
TFTP_ERROR      = 5;
TFTP_OACK       = 6;
TFTP_BLOCK_SIZE = 1024; # Use 1024 to stay under the max ip size

##
# Download a file from a remote TFTP server. 
#
# @param port The port number, probably 69.
# @param path The path of the file to download.
#
# @return The file, as a string.
##
function tftp_get(port, path)
{
  local_var s, dport, sport, block, block_num, block_size, file, response, code, error, message, option;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Create a non-connected udp port
  s = bind_sock_udp();
  if(!s)
    exit(1, "failed to bind socket");

  # Get the socket and target port from the return
  sport = s[1];
  s     = s[0];

  # Send the initial request, including our desired blocksize, to port 69
  sendto(socket:s, data:mkword(TFTP_RRQ) + path + '\x00octet\x00BLKSIZE\0' + TFTP_BLOCK_SIZE + '\0', dst:get_host_ip(), port:port);

  # Default to TFTP's default blocksize till it acknowledges our request
  # This is less than the BLOCK_SIZE constant on purpose - we don't assume
  # the server figured out the proper BLOCK_SIZE till we're done. 
  block_size = 512;
  file = '';
  while(TRUE)
  {
    # Get the response on a potentially different port
    response = recvfrom(socket:s, port:sport, src:get_host_ip(), timeout:30);
    if(!response)
      exit(1, "Failed to receive data from the TFTP server");
    dport    = response[2];
    response = response[0];

    # Read the code and remove it from the front of the packet
    code     = getword(blob:response, pos:0);
    response = substr(response, 2);

    # Take the appropriate action based on the code
    if(code == TFTP_DATA)
    {
      block_num = getword(blob:response, pos:0);
      block = substr(response, 2);
      
      file = file + block;

      # Send the acknowledgement
      sendto(socket:s, data:mkword(TFTP_ACK) + mkword(block_num), dst:get_host_ip(), port:dport);

      # When we get an incomplete block, we're finished reading - this needs
      # to be after the ACK
      if(strlen(block) != TFTP_BLOCK_SIZE)
        break;
    }
    else if(code == TFTP_ERROR)
    {
      error = getword(blob:response, pos:0);
      message = substr(response, 2);

      exit(1, "TFTP Error: " + message);
    }
    else if(code == TFTP_OACK)
    {
      option = split(substr(response, 2), sep:'\0', keep:FALSE);
      if(option[0] = 'BLKSIZE')
        block_size = int(option[1]);
      sendto(socket:s, data:mkword(TFTP_ACK) + mkword(0), dst:get_host_ip(), port:dport);
    }
    else
    {
      exit(1, "Unexpected response code from TFTP server: " + code);
    }
  }

  return file;
}

##
# Upload a file to a remote TFTP server. 
#
# @param port The port number, probably 69.
# @param path The path where the file will be put.
# @param data The file data.
##
function tftp_put(port, path, data)
{
  local_var s, dport, sport, block, block_num, block_size, file, response, code, error, message, option;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Create a non-connected udp port
  s = bind_sock_udp();
  if(!s)
    exit(1, "failed to bind socket");

  # Get the socket and target port from the return
  sport = s[1];
  s     = s[0];

  # Send the initial request, including our desired blocksize, to port 69
  sendto(socket:s, data:mkword(TFTP_WRQ) + path + '\x00octet\x00', dst:get_host_ip(), port:port);

  # Default to TFTP's default blocksize till it acknowledges our request
  # This is less than the BLOCK_SIZE constant on purpose - we don't assume
  # the server figured out the proper BLOCK_SIZE till we're done. 
  block_size = 512;
  file = '';
  while(TRUE)
  {
    # Get the response on a potentially different port
    response = recvfrom(socket:s, port:sport, src:get_host_ip(), timeout:30);
    if(!response)
      exit(1, "Failed to receive data from the TFTP server");
    dport    = response[2];
    response = response[0];

    # Read the code and remove it from the front of the packet
    code     = getword(blob:response, pos:0);
    response = substr(response, 2);

    # Take the appropriate action based on the code
    if(code == TFTP_ACK)
    {
      # Send the next block
      block_num = getword(blob:response, pos:0);

      if(block_num * block_size > strlen(data))
        break;

      sendto(socket:s, data:mkword(TFTP_DATA) + mkword(block_num + 1) + substr(data, block_size * block_num, (block_size * block_num) + block_size - 1), dst:get_host_ip(), port:dport);
    }
    else if(code == TFTP_ERROR)
    {
      error = getword(blob:response, pos:0);
      message = substr(response, 2);

      exit(1, "TFTP Error: " + message);
    }
    else
    {
      exit(1, "Unexpected response code from TFTP server: " + code);
    }
  }
}

#### Functions added by Michel Arboi <mikhail@nessus.org> ####

# The 1st function is necessary as TFTP is UDP based and not 100% reliable
# All TFTP scripts should call it to test returned data & avoid false alerts
function tftp_ms_backdoor(data, port, file)
{
 if (strlen(data) > 40 && substr(data, 0, 1) == 'MZ')
   if ('\x50\x45\x00\x00' >< data )
     report_tftp_backdoor(port: port, file: file, type: 'MS PE', data: data);
   else if ('This program cannot be run in DOS mode' >< data ||
   	    'This program must be run under Win32' >< data)
     report_tftp_backdoor(port: port, file: file, type: 'MS', data: data);
}

function report_tftp_backdoor(port, file, type, data)
{
 local_var	a, c, k;

 c = tolower(type[0]);
 if (c == 'm' || c == 'a' || c == 'e' || c == 'x') a = 'an '; else a = 'a ';

 security_hole(port: port, proto: 'udp', data: 
'
Synopsis :

The remote host has probably been compromised. 

Description :

A TFTP server is running on this port. However, while trying to 
fetch "'+ file + '", we got '+ a + type + ' executable file. 

Many worms are known to propagate through TFTP.  This is probably a
backdoor. 

Solution : 

Disinfect / reinstall the system.

Risk factor :

Critical / CVSS Base Score : 10.0
(CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C)');
 if (port == 69)
  set_kb_item(name: 'tftp/backdoor', value: TRUE);
 set_kb_item(name: 'tftp/'+port+'/backdoor', value: TRUE);

 if (strlen(data) > 0 )
 {
   k = '/tmp/antivirus/UDP/'+port;
   if (! get_kb_item(k)) set_kb_item(name: k, value: hexstr(data));
 }
 exit(0);
}

