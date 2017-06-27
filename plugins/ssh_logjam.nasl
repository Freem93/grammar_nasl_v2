#TRUSTED 4a52c7429324fa93b26116c2d158c7fd3a3fe91fb233424e2b1c2b3c57a833188bfbd2b7a5205e0943005c46540ded88af362b0a1a487fc57550396255f3a4ac229e69282c93d4475d15ea5dd328e39d104cdbd6b1eaa716ec31ac210caa895c76e51dfadf227461edeae1b95ed847dc706cb58d968c245bb084a965e33e0e1f10992d3864fc9ef2f88fa179271676951eecf649b94510b2fc802a563127578d1c0ec9f1540a20f51157647eae9c4d98ef2029d7178e505e3045bc35ea494759b200431e54743e7bee302a2336d6cfef08f695bc5a1e5d1401e4113671c11f017bec8fa96fe95b35598dcd70bacfd0c6588da052cb5b34aff4681dd1e45b8ec23c9ee9558977a15548020dbe76de640afeb2a99db33208cd329fa0af623f9e93cdd5703f9a1f6654a7b833c9b364cfc9f3fbb5b560d667b9258e69de7a2542037fda1cddbef284fd0ef6b2ee89f32d973dfdbfa1224b738f7dc58a898164524c9c533a355bdb2402f629dbb4e3191a41f11311f119364643957651d0d2ab83df7db010771a28ee270cfb4516bcd53e54bab793eb75bc9b9364e893b5fbf1adc21eee8c276f3056036e9e4bdb8f23accdf67617b10de487b7139031d7cabe19832871dea60a574c50f6d39f0b8294c4bd747412fa4dd30c3d5f670b03d8b099bdb028d444b05fe743f46c24b969b812753d0274c5c7a7acf5ca809f7387399201
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86328);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/20");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_osvdb_id(122331);

  script_name(english:"SSH Diffie-Hellman Modulus <= 1024 Bits (Logjam)");
  script_summary(english:"Checks to see what DH modulus sizes are being used.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows SSH connections with one or more Diffie-Hellman
moduli less than or equal to 1024 bits.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server allows connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits. Through
cryptanalysis, a third party can find the shared secret in a short
amount of time (depending on modulus size and attacker resources).
This allows an attacker to recover the plaintext or potentially
violate the integrity of connections.");
  script_set_attribute(attribute:"see_also", value:"http://weakdh.org/");
  script_set_attribute(attribute:"see_also", value:"https://stribika.github.io/2015/01/04/secure-secure-shell.html");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to use a unique Diffie-Hellman moduli of 2048
bits or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_dependencies("find_service.nasl");
  script_require_keys("Services/ssh", "Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("audit.inc");

##
# Checks to see if the server can be forced to use a DH
# group exchange with a modulus smaller than or equal to
# 1024
#
# @param socket : socket of SSH sever
# @param port   : port for socket (used in exit messages)
#
# @remark exits with message when network failure occurs
#
# @return TRUE  if the server supports a GEX with 1024 mod
#         FALSE if the server does not allow this
##
function can_force_dh_gex_1024(socket, port)
{
  if(isnull(socket))
    socket = _FCT_ANON_ARGS[0];
  if(isnull(socket))
    return FALSE;

  local_var key_exchange_algo        = "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1";
  local_var server_host_key_algo     = "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-rsa,ssh-dss";
  local_var enc_alg_client_to_server = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc";
  local_var mac_alg_client_to_server = "hmac-sha1";
  local_var cmp_alg_client_to_server = "none";
  local_var enc_alg_server_to_client = enc_alg_client_to_server;
  local_var mac_alg_server_to_client = mac_alg_client_to_server;
  local_var cmp_alg_server_to_client = cmp_alg_client_to_server;

  # Initialize key exchange
  local_var ccookie = "";
  while(strlen(ccookie) < 16)
    ccookie += raw_int8(rand()%256);
  local_var data =
    ccookie +                              # cookie
    putstring(key_exchange_algo) +         # kex_algorithms
    putstring(server_host_key_algo) +      # server_host_key_algorithms
    putstring(enc_alg_client_to_server) +  # encryption_algorithms_client_to_server
    putstring(enc_alg_server_to_client) +  # encryption_algorithms_server_to_client
    putstring(mac_alg_client_to_server) +  # mac_algorithms_client_to_server
    putstring(mac_alg_server_to_client) +  # mac_algorithms_server_to_client
    putstring(cmp_alg_client_to_server) +  # compression_algorithms_client_to_server
    putstring(cmp_alg_server_to_client) +  # compression_algorithms_server_to_client
    raw_int32(0) +                         # languages_client_to_server
    raw_int32(0) +                         # languages_server_to_client
    crap(data:raw_string(0x00), length:5); # payload
  data = kex_packet(payload:data, code:SSH_MSG_KEXINIT);
  send(socket:socket, data:data);

  # Try to force 1024 bit modulus
  data =
    raw_int32(128)  + # min key length
    raw_int32(1024) + # preferred key length
    raw_int32(1024);  # max key length
  data = kex_packet(payload:data, code:SSH_MSG_KEXDH_GEX_REQUEST);
  send(socket:socket, data:data);

  data = recv(socket:socket, length:1000);

  # Newer versions of OpenSSH appear to just not respond at all
  # if you have a maximum moduli value below their min moduli
  if(isnull(data))
    return FALSE;

  # Anything other than KEXDH_REPLY probably means the server sent us an error back
  if(ord(data[5]) != SSH_MSG_KEXDH_REPLY)
    return FALSE;

  data = packet_payload(packet:data, code:SSH_MSG_KEXDH_REPLY);

  # Also shouldn't happen
  if(!data)
  {
    close(socket);
    exit(1, "The SSH server on port "+port+" did not respond as expected to the group exchange request.");
  }

  # Check the mod length
  local_var p = getstring(buffer:data, pos:0);
  if(strlen(p)-1 <= (1024 / 8))
    return TRUE;

  return FALSE;
}

port = get_kb_item_or_exit("Services/ssh"); # this will branch
client_ver = 'SSH-2.0-OpenSSH_6.4\r\n';

# Only nation states might have the processing power to
# exploit this and nearly all SSH implementations will be
# flagged
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Server vulnerable if report is not blank
report = "";

# Negotiate connection
soc = open_sock_tcp(port);
if(!soc)
  audit(AUDIT_SOCK_FAIL, port);

# Exchange versions
server_ver = recv(socket:soc, length:1024);
if(isnull(server_ver))
  audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);
if("SSH-2.0" >!< server_ver && "SSH-1.99" >!< server_ver)
  audit(AUDIT_NOT_LISTEN, "SSH 2.0 Server", port);
send(socket:soc, data:client_ver);

# Check and make sure we got valid KEX INIT data
server_kex_dat = recv(socket:soc, length:2048);
if(isnull(server_kex_dat) || ord(server_kex_dat[5]) != SSH_MSG_KEXINIT)
{
  close(soc);
  exit(1, "The SSH server on port "+port+" did not send key exchange data.");
}

# Check key exchange for weaknesses
if("diffie-hellman-group1-sha1" >< server_kex_dat)
{
  report += 
    '  It supports diffie-hellman-group1-sha1 key\n' +
    '  exchange.\n\n';
}
if("diffie-hellman-group-exchange-sha1" >< server_kex_dat && can_force_dh_gex_1024(soc,port:port))
{
  report += 
    '  It supports diffie-hellman-group-exchange-sha1\n' +
    '  key exchange and allows a moduli smaller than\n' +
    '  or equal to 1024.\n\n';
}
close(soc);

if(report != "")
{
  if(report_verbosity > 0)
  {
    # This is a hard attack ... for now.
    report =
    'The SSH server is vulnerable to the Logjam attack because :\n\n' +
    report +
    'Note that only an attacker with nation-state level resources\n' +
    'can effectively make use of the vulnerability, and only\n' +
    'against sessions where the vulnerable key exchange\n' +
    'algorithms are used.\n';
    security_note(port:port,extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SSH Server", port);
