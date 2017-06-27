#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42818);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/06/15 01:43:59 $");

  script_name(english:"Lotus Domino Console Detection");
  script_summary(english:"Detects Lotus Domino server console");

  script_set_attribute(attribute:"synopsis", value:"An administration console is running on this port.");
  script_set_attribute(attribute:"description", value:
"The Lotus Domino console is running on this port. 

A dedicated client software uses this console port to reconfigure the
Domino server.  Credentials are needed for that operation.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 2050);

  exit(0);
}

include("global_settings.inc");
include("x509_func.inc");

port = get_kb_item("Services/unknown");
if (!port) port = 2050;

t = get_port_transport(port);
if (t == ENCAPS_IP) exit(0);

v = get_unknown_banner2(port: port, ipproto: "tcp",  dontfetch: 1);
if (isnull(v)) exit(0);
if (v[1] == "spontaneous") exit(0);
if (v[0] != 'BAD_COMMAND\n') exit(0);

cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(0);
cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(0);
tbs = cert["tbsCertificate"];
subject = tbs["subject"];

z = make_array();
foreach n (subject)
{
  o = oid_name[n[0]];
  if (! isnull(o)) { z[o] = n[1]; }
}

# /CN=DominoConsole/OU=Iris/O=Lotus Development Corporation/L=Westford/ST=MA/postalCode=01886/C=US
cn = z["Common Name"];
ou = z["Organization Unit"];
o  = z["Organization"];
l  = z["Locality"];
st = z["State/Province"];
pc = z["Postal Code"];
c  = z["Country"];

if (cn == "DominoConsole" && ou == "Iris" &&
    o == "Lotus Development Corporation" && l == "Westford" && st == "MA" &&
    pc == "01886" && c == "US")
{
  register_service(port: port, proto: "domino_console");
  security_note(port);
}
