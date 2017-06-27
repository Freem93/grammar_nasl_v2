#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_version("$Revision: 1.5 $");
  script_id(35951);

  script_name(english:"Samhain Server (yule) Detection");
  script_summary(english:"Detects the presence of a Samhain server");

  script_set_attribute( attribute:"synopsis", value:
"A host-based intrusion detection system (HIDS) service is listening
on the remote host."  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running a Samhain server (yule).  Samhain is a
host-based intrusion detection system that also provides centralized
logging and management."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.la-samhna.de/samhain/"
  );
  script_set_attribute( attribute:"solution",  value:
"Make sure that use of this software agrees with your organization's
security policy."  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );

    
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/17");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
 
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
  
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 49777);
  
  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


client_pubkey = rand_str(charset:"0123456789ABCDEF", length:256);
SH_PROTO_SRP = 1;                      # protocol
usernames = make_list("127.0.0.1", "localhost", get_host_name(), get_host_ip(),
                      this_host(), this_host_name());


if (thorough_tests)
{
  port = get_unknown_svc(49777);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0);
}
else port = 49777;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


function attempt_login(username, port)
{
  local_var soc, request, response, len, samhain_detected;
  samhain_detected = FALSE;

  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Send a client request salt.
  request = mkbyte(SH_PROTO_SRP) +
    mkword(strlen(username)) +
    "SALT" +
    username;
  send(socket:soc, data:request);
  
  #the server will reply with "INIT" and the length of the salt
  response = recv(socket:soc, length:7);
  if (
    strlen(response) == 7 &&
    getbyte(blob:response, pos:0) == SH_PROTO_SRP &&
    substr(response, 3) == "INIT"
  )
  {
    len = getword(blob:response, pos:1);

    #Receives the salt from the server
    if (len > 0)
    {
      response = recv(socket:soc, length:len);

      if (
        strlen(response) == len &&
        response =~ "^[0-9A-F]+$"
      )
      {
        #Sends the client public key to the server
        request = mkbyte(SH_PROTO_SRP) +
          mkword(strlen(client_pubkey)+1) +
          "PC01" + 
          client_pubkey + mkbyte(0);
        send(socket:soc, data:request);

        #The server should reply with the len of its public key,
        #and a 4 byte nonce		
        response = recv(socket:soc, length:7);

        if (
          strlen(response) == 7 &&
          getbyte(blob:response, pos:0) == SH_PROTO_SRP
        )
        {
          len = getword(blob:response, pos:1);

          if (len > 0)
          {
            response = recv(socket:soc, length:len);

            #if the server's public key was successfully received,
            #this is most likely a samhain server
            if (
              strlen(response) == len &&
              getbyte(blob:response, pos:len) == 0 &&
              substr(response, 0, len-1) =~ "^[0-9A-F]+$"
            )
            {
              samhain_detected = TRUE;
            }
          }
        }
      }
    }
  }
  close(soc);

  return samhain_detected;
}


foreach username ( usernames )
{
  if(attempt_login(username:username, port:port))
  {
    # Register and report the service.
    register_service(port:port, proto:"samhain");
    set_kb_item(name:"Services/samhain/username", value:username);
    security_note(port);
    exit(0);
  }
}
