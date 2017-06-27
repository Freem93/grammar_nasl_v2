#
# (C) Tenable Network Security, Inc. 
#

if ( NASL_LEVEL < 2205 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(27576);
 script_version ("$Revision: 1.16 $");
 script_name(english: "Firewall Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is behind a firewall." );
 script_set_attribute(attribute:"description", value:
"Based on the responses obtained by the SYN or TCP port scanner, it was 
possible to determine that the remote host seems to be protected by a 
firewall." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/26");
 script_cvs_date("$Date: 2012/02/22 18:38:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines if the remote host is behind a firewall");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english: "Firewalls");
 script_dependencies("find_service1.nasl");
 exit(0);
}
include("global_settings.inc");


global_var	ps_ran;
ps_ran = 0;

function test(scanner, prefix)
{
  local_var	open, closed, filtered, total;

  if ( ! get_kb_item("Host/scanners/"+scanner)) return 0;
  ps_ran ++;

  if (get_kb_item(prefix+"/RSTRateLimit"))
    exit(1, scanner+" detected RST rate limitation.");

  open = int(get_kb_item(prefix+"/OpenPortsNb"));
  closed = int(get_kb_item(prefix+"/ClosedPortsNb"));
  filtered = int(get_kb_item(prefix+"/FilteredPortsNb"));
  total = open + closed + filtered;
  if (total == 0) return 0;
  if (filtered == 0) exit(0, "No filtered port was detected by "+scanner+".");

  if ( filtered > ( closed * 4 ) )
    return 1;
  else
    return 0;
}

# The SYN scanner is probably more sensitive
flag1 = test(scanner: "nessus_syn_scanner", prefix: "SYNScanner");
flag2 = test(scanner: "nessus_tcp_scanner", prefix: "TCPScanner");

if (flag1 || flag2)
{
  if ( report_paranoia >= 2 ) security_note(0);
  set_kb_item(name:"Host/firewalled", value:TRUE);
  exit(0);
}
else
  if (ps_ran)
    exit(0, "Too few filtered ports were detected.");
  else
    exit(0, "The port scanners did not run.");

