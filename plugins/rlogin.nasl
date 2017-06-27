#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10205);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_cve_id("CVE-1999-0651");
 script_osvdb_id(193);

 script_name(english:"rlogin Service Detection");
 script_summary(english:"Checks for the presence of rlogin.");

 script_set_attribute(attribute:"synopsis", value:
"The rlogin service is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The rlogin service is running on the remote host. This service is
vulnerable since data is passed between the rlogin client and server
in cleartext. A man-in-the-middle attacker can exploit this to sniff
logins and passwords. Also, it may allow poorly authenticated logins
without passwords. If the host is vulnerable to TCP sequence number
guessing (from any network) or IP spoofing (including ARP hijacking on
a local network) then it may be possible to bypass authentication.
Finally, rlogin is an easy way to turn file-write access into full
logins through the .rhosts or rhosts.equiv files.");
 script_set_attribute(attribute:"solution", value:
"Comment out the 'login' line in /etc/inetd.conf and restart the inetd
process. Alternatively, disable this service and use SSH instead.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'rlogin Authentication Scanner');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1990/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rlogin", 513);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

function test(port)
{
  local_var	soc, s, c, a, r;

  if (! get_port_state(port)) return 0;
  soc = open_priv_sock_tcp(dport:port);
  if (! soc) return 0;
  s = '\0';
  send(socket:soc, data:s);
  s = 'root\0root\0xterm/38400\0';
  send(socket:soc, data:s);
  c = recv(socket:soc, length: 1);
  if (strlen(c) == 0 || c != '\0')
  {
    close(soc);
    return 0;
  }
  r = recv(socket:soc, length:1024);
  close(soc);
  a = strcat(c, r);
  set_kb_banner(port: port, type: "rlogin", banner: a);
  if (strlen(r) < 1) return 0;
  if (port == 513 || 'assword:' >< r)
    return 1;
  else
    return 0;
}

port_l = make_service_list(513, "Services/rlogin");
done = make_list();

foreach p (port_l)
  if (! done[p])
  {
    if (test(port: p))
    {
      pci_report = 'The remote RLOGIN service on port ' + p + ' accepts cleartext logins.';
      set_kb_item(name:"PCI/ClearTextCreds/" + p, value:pci_report);
      security_hole(port: p);
      register_service(port: p, proto: "rlogin");
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
        pci_report = 'The remote RLOGIN service on port ' + p + ' accepts cleartext logins.';
        set_kb_item(name:"PCI/ClearTextCreds/" + p, value:pci_report);
        security_hole(port: p);
        register_service(port: p, proto: "rlogin");
      }
      done[p] = 1;
    }
