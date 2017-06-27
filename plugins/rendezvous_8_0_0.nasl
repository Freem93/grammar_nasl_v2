#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(28376);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-4158");
  script_bugtraq_id(25132);
  script_osvdb_id(37680);

  script_name(english:"Rendezvous < 8.0.0 Crafted Packet Remote DoS");
  script_summary(english:"Checks version of Rendezvous browser admin interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is prone to a denial of
service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Rendezvous, a commercial
messaging software product used for building distributed applications

According to its banner, Rendezvous' rvd daemon fails to properly
validate input in incoming packets before using it to allocate memory. 
By sending a specially crafted packet with a length field of 0, an
unauthenticated, remote attacker may be able to leak memory and
eventually exhaust memory on the affected system." );
 # http://web.archive.org/web/20071215011534/http://www.irmplc.com/index.php/160-Advisory-025
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab43b01a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TIBCO Rendezvous version 8.0 or later as that reportedly
addresses the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/31");
 script_cvs_date("$Date: 2013/06/12 15:45:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7580, 7585);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");
if (!port) port = 7580;
if (!get_port_state(port)) exit(0);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("Rendezvous HTTP Server " >< banner)
{
  version = strstr(banner, "Rendezvous HTTP Server ") - "Rendezvous HTTP Server ";
  if (version =~ "^[0-7]\.")
  {
    report = string(
      "The Rendezvous browser administration interface on the remote host\n",
      "returned the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_hole(port:port, extra:report);
  }
}
