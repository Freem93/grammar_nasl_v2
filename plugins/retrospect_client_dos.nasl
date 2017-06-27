#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20996);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0995");
  script_bugtraq_id(16933);
  script_osvdb_id(23613);

  script_name(english:"Retrospect Client Malformed Packet DoS");
  script_summary(english:"Checks version of Retrospect client");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup client is susceptible to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installed instance of Retrospect
Client for Windows reportedly will stop working if it receives a
packet starting with a specially crafted sequence of bytes.  An
unauthenticated, remote attacker may be able to leverage this flaw to
prevent the affected host from being backed up." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426652/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad9dbb3d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Retrospect Client for Windows version 6.5.138 / 7.0.109 or
later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/02");
 script_cvs_date("$Date: 2011/09/23 17:42:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("retrospect_detect.nasl");
  script_require_ports("Services/retrospect", 497);

  exit(0);
}


port = get_kb_item("Services/retrospect");
if (!port) port = 497;
if (!get_port_state(port)) exit(0);


ver = get_kb_item(string("Retrospect/", port, "/Version"));
ostype = get_kb_item(string("Retrospect/", port, "/OSType"));
if (!ver || isnull(ostype))
  exit (0);

# Windows only
ostype = ostype >>> 16;

if (ostype > 1 && ostype < 10)
{
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 138) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 109)
  ) security_warning(port);
}
