#
# (C) David Lodge 13/08/2007
# This script is based on sybase_blank_password.nasl which is (C) Tenable Network Security, Inc.
#
# This script is released under the GPLv2
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11)
# - Revised plugin title (6/12/09)
# - Add global_settings/supplied_logins_only script_exclude_key and
# - use global_settings.inc and check port state (06/2015)


include("compat.inc");

if(description)
{
  script_id(25927);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_name(english:"Sybase ASA Default Database Password");
  script_summary(english:"ASA Default Database Password.");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to connect to the remote database service using default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Sybase SQL Anywhere / Adaptive Server Anywhere server uses
default credentials ('DBA' / 'SQL').  An attacker may use this flaw to
execute commands against the remote host, as well as read your
database content.");
  script_set_attribute(attribute:"solution", value:
"Change the default password." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2015 David Lodge");

  script_require_ports("Services/sybase", 2638);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


#
# The script code starts here
#
include("global_settings.inc");

login_pkt_hdr = raw_string(
   0x02,        # Login packet type
   0x00,        # Not last packet
   0x02, 0x00,  # Size of packet
   0x00, 0x00,  # Channel
   0x00,        # Packet Number
   0x00         # Window
);

login_pkt_hdr2 = raw_string(
   0x02,        # Login packet type;
   0x01,        # Not last packet
   0x00, 0x61,  # Size of packet
   0x00, 0x00,  # Channel
   0x00,        # Packet Number
   0x00         # Window
);

nul=raw_string(0x00);

# data for hostname including length
pkt_src_hostname = crap(data:nul, length:31);
# username is here
# password is here
pkt_src_process = raw_string("1",crap(data:nul, length:29), 0x01);
pkt_magic1 = raw_string(
   0x03, 0x01, 0x06, 0x0a, 0x09, 0x01
);
pkt_bulk_copy = raw_string(0x00);
pkt_magic2 = crap(data:nul, length:9);
pkt_client = raw_string("nessus", crap(data:nul, length:24), 0x06);
# database is here
pkt_magic3 = raw_string(0x00);
# password repeats here but with length first!
pkt_magic4 = crap(data:nul, length:223);
pkt_passwordlength_plus2 = raw_string (0x05);
pkt_version = raw_string(0x05, 0x00, 0x00, 0x00);
pkt_library = raw_string("CT-Library", 0x0a);
pkt_library_version = raw_string(0x05, 0x00, 0x00, 0x00);
pkt_magic6 = raw_string(0x00, 0x0d, 0x11);
pkt_language = raw_string("us_english", crap(data:nul, length:14));
pkt_language2 = raw_string(crap(data:nul, length:6),0x0a);
pkt_magic7 = raw_string(0x00);
pkt_old_secure = raw_string(0x00, 0x00);
pkt_encrypted = raw_string(0x00);
pkt_magic8 = raw_string(0x00);
pkt_sec_spare = crap(data:nul, length:9);
pkt_char_set = raw_string("UTF-8", crap(data:nul, length:25), 0x05);
pkt_magic9 = raw_string(0x01);
pkt_block_size = raw_string("512",0x00,0x00,0x00,0x03);
pkt_magic10 = raw_string(
   0x00, 0x00, 0x00, 0x00, 0xe2, 0x16, 0x00, 0x01, 0x09, 0x00,
   0x00, 0x06, 0x6d, 0x7f, 0xff, 0xff, 0xff, 0xfe, 0x02, 0x09,
   0x00, 0x00, 0x00, 0x00, 0x0a, 0x68, 0x00, 0x00, 0x00
);
   
function make_sql_login_pkt(database, username, password)
{
    local_var dblen, dbuf, dlen, dpad, pblen, pbuf, plen, ppad, sql_packet, ublen, ubuf, ulen, upad;

    dlen = strlen(database);
    ulen = strlen(username);
    plen = strlen(password);
    
    dpad = 30 - dlen;
    upad = 30 - ulen;
    ppad = 30 - plen;
    
    dbuf = "";
    ubuf = "";
    pbuf = "";
    
    nul = raw_string(0x00);
    
    if(ulen)
    {
        ublen = raw_string(ulen % 255);
    } else {
        ublen = raw_string(0x00);
    }
    
    if(plen)
    {
        pblen = raw_string(plen % 255);
    } else {
        pblen = raw_string(0x00);
    }  

    if(dlen)
    {
        dblen = raw_string(dlen % 255);
    } else {
        dblen = raw_string(0x00);
    }  

    dbuf = string(database, crap(data:nul, length:dpad));
    ubuf = string(username, crap(data:nul, length:upad));
    pbuf = string(password, crap(data:nul, length:ppad));

    sql_packet = string( 
       login_pkt_hdr, pkt_src_hostname, ubuf, ublen, pbuf, pblen,
       pkt_src_process, pkt_magic1, pkt_bulk_copy, pkt_magic2,
       pkt_client, dbuf, dblen, pkt_magic3, pblen, pbuf, pkt_magic4,
       pkt_passwordlength_plus2, pkt_version, pkt_library,
       pkt_library_version, pkt_magic6, pkt_language, login_pkt_hdr2,
       pkt_language2,
       pkt_magic7, pkt_old_secure, pkt_encrypted, pkt_magic8,
       pkt_sec_spare, pkt_char_set, pkt_magic9, pkt_block_size,
       pkt_magic10
    );

    # returning this as a string is NOT working!
    return sql_packet;
}

port = get_kb_item("Services/sybase");
if(!port)port = 2638;
if (!get_port_state(port)) exit(0, "Port " +port+ " is not open.");

if (supplied_logins_only) exit(0, "Policy is configured to prevent trying default user accounts");

soc = open_sock_tcp(port);

if(soc)
{
  # this creates a variable called sql_packet
  sql_packet = make_sql_login_pkt(database:"", username:"DBA", password:"SQL");
  send(socket:soc, data:sql_packet);

  r  = recv(socket:soc, length:512);
  close(soc);

  # See <http://www.freetds.org/tds.html> for info on the TDS protocol
  if(
    # packet seems big enough and...
    strlen(r) > 3 &&
    # response from server and...
    ord(r[0x00]) == 4 &&
    # packet length agrees with what's in the packet header
    (ord(r[2])*256 + ord(r[3])) == strlen(r)
  )
  {
    # Find the server response to the login request.
    i = 8;
    while (i < strlen(r))
    {
      type = ord(r[i]);
      if (type == 0xFD || type == 0xFE || type == 0xFF)
      {
        exit(0);
      }
      if (type == 0xAD)
      {
        ack = ord(r[i+3]);
        ver = ord(r[i+4]);
        if (
          (ver == 5 && ack == 5) ||
          (ver == 4 && ack == 1)
        )
        {
          security_hole(port);
          exit(0);
        }
      }
      len = ord(r[i+1]) + ord(r[i+2])*256;
      i += 3 + len;
    }
  }
}
