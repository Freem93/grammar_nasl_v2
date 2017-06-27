#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(14234);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2004-2486");
  script_bugtraq_id(10803);
  script_osvdb_id(8137);

  script_name(english:"Dropbear SSH Server DSS Verification Failure Remote Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dropbear prior to version 0.43.  
There is a flaw in this version of Dropbear that could
enable a remote attacker to gain control of the system
from a remote location." );
 script_set_attribute(attribute:"see_also", value:"http://matt.ucc.asn.au/dropbear/CHANGES" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to at least version 0.43 of Dropbear." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/16");
 script_cvs_date("$Date: 2016/10/17 13:39:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:matt_johnston:dropbear_ssh_server");
script_end_attributes();

 
  script_summary(english:"Dropbear remote DSS SSH vuln check");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");
  exit(0);
}



port = get_kb_item ("Services/ssh"); 
if (!port) port = 22;
if (!get_port_state (port)) exit (0);

banner = get_kb_item("SSH/banner/" + port );

if (! banner) exit(0);

# version 0.28 thru 0.42 are vulnerable
if (egrep(string:banner, pattern:"-dropbear_0\.(2[0-9]|3[0-9]|4[0-2])") )
	security_hole(port);

