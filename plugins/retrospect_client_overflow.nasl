#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21327);
  script_version("$Revision: 1.23 $");
  script_cve_id("CVE-2006-2391");
  script_bugtraq_id(17948, 18064);
  script_osvdb_id(25502);
  script_xref(name:"CERT", value:"186944");

  script_name(english:"EMC Retrospect Client Packet Handling Remote Overflow");
  script_summary(english:"Checks version of Retrospect client");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote backup client." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installed instance of Retrospect
client is susceptible to a buffer overflow attack that can be
triggered by a packet starting with a specially crafted sequence of
bytes. 

An unauthenticated, remote attacker may be able to exploit this flaw to
execute code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.acrossecurity.com/aspr/ASPR-2006-05-17-1-PUB.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434726/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://kb.dantz.com/article.asp?article=9511&p=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version of Retrospect Client." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/04");
 script_cvs_date("$Date: 2012/12/10 03:02:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
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

major = ostype >>> 16;
minor = ostype & 0xFFFF;
iver = split(ver, sep:'.', keep:FALSE);

# Windows
if (major > 1 && major < 10)
{
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 140) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 112) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 116)
  ) security_hole(port);
}

# NetWare
if (major > 10)
{
  if (
    (int(iver[0]) == 1 && int(iver[1]) == 0 && int(iver[2]) < 141)
  ) security_hole(port);
}

# Unixes
if (major == 0)
{
 # Redhat
 if (minor == 0)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 112)
  ) security_hole(port);

 # Solaris
 if (minor == 1)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 5 && int(iver[2]) < 110) ||
    (int(iver[0]) == 7 && int(iver[1]) == 0 && int(iver[2]) < 109) ||
    (int(iver[0]) == 7 && int(iver[1]) == 5 && int(iver[2]) < 112)
  ) security_hole(port);

 # Mac OS X
 if ((minor >> 8) == 0x10)
  if (
    (int(iver[0]) == 6 && int(iver[1]) == 0) ||
    (int(iver[0]) == 6 && int(iver[1]) == 1 && int(iver[2]) < 130)
  ) security_hole(port);
}

