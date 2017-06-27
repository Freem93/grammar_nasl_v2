#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10245);
 script_version ("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_cve_id("CVE-1999-0651");
 script_osvdb_id(193);

 script_name(english:"rsh Service Detection");
 script_summary(english:"Checks for the presence of rsh.");

 script_set_attribute(attribute:"synopsis", value:
"The rsh service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The rsh service is running on the remote host. This service is
vulnerable since data is passed between the rsh client and server
in cleartext. A man-in-the-middle attacker can exploit this to sniff
logins and passwords. Also, it may allow poorly authenticated logins
without passwords. If the host is vulnerable to TCP sequence number
guessing (from any network) or IP spoofing (including ARP hijacking on
a local network) then it may be possible to bypass authentication.
Finally, rsh is an easy way to turn file-write access into full
logins through the .rhosts or rhosts.equiv files.");
 script_set_attribute(attribute:"solution", value:
"Comment out the 'rsh' line in /etc/inetd.conf and restart the inetd
process. Alternatively, disable this service and use SSH instead." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'rlogin Authentication Scanner');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "1990/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 # We could run after find_service1.nasl, but in paranoid mode, some services
 # could be wrongly identified as "rsh"
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/rsh", 514);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

function test(port)
{
 local_var	soc, s1, s2, c, r, a;
 local_var	from, user, ret, den;

 if (! get_port_state(port)) return 0;
 from = "root"; user = "root";
 ret = 0;
 soc = open_priv_sock_tcp(dport:port);
 if( !soc) return 0;
 s1 = '0\0';		# No separate channel for errors
 s2 = strcat(
	from, '\0',	# login from
	user, '\0',	# login as
	'id\0' );	# Command
  send(socket:soc, data:s1);
  send(socket:soc, data:s2);
  c = recv(socket: soc, length: 1);
  if (strlen(c) < 1)
    close(soc);
  else
  {
    r = recv(socket: soc, length: 8192);
    close(soc);
    a = strcat(c, r);
    set_kb_banner(port: port, type:"rsh", banner: a);
    if (strlen(r) > 0)
    {
      if (c == '\0') 	# Success
      {
        den = egrep(string: r, pattern: '(permission|access) (is )?denied', icase: 1);
        if (port == 514 || 
	    ereg(string: r, pattern: "uid=[0-9]") || 
	    strlen(den) > 0 ||	# Windows SFU answers "\0Access is denied"
	    'id:' >< r)		# Something like "Command not found"
	{
	  if (strlen(den) == 0)
	  {
	    set_kb_item(name: "rsh/login_from", value: from);
	    set_kb_item(name: "rsh/login_to", value: user);
	  }
	  return 1;
	}
      }
      else	# Failure
      {
        if (report_paranoia > 1 ||
	    'assword:' >< r ||
	    strlen(den) > 0)
	{
	  return 1;
	}
      }
    }
  }
  return 0;
}

# Main

ports_l = make_service_list(514, "Services/rsh");

foreach p (ports_l)
  if (! done[p])
  {
    if (test(port: p))
    {
      pci_report = 'The remote RSH service on port ' + p + ' accepts cleartext logins.';
      set_kb_item(name:"PCI/ClearTextCreds/" + p, value:pci_report);
      set_kb_item(name:"rsh/active", value:TRUE);
      register_service(port: p, proto: "rsh");
      security_hole(port: p);
    }
    done[p] = 1;
  }

if (! get_kb_item("global_settings/disable_service_discovery")
    && thorough_tests)
  foreach p (get_kb_list("Services/unknown"))
    if (! done[p] && service_is_unknown(port: p))
    {
      if (test(port: p))
      {
  pci_report = 'The remote RSH service on port ' + p + ' accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + p, value:pci_report);
	set_kb_item(name:"rsh/active", value:TRUE);
	register_service(port: p, proto: "rsh");
	security_hole(port: p);
      }
      done[p] = 1;
    }
