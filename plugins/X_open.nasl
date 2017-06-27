#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(19948);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_cve_id("CVE-1999-0526");
  script_osvdb_id(309);

  script_name(english:"X11 Server Unauthenticated Access");
  script_summary(english:"X11 determines if X11 is open.");

  script_set_attribute(attribute:"synopsis", value:
"The remote X11 server accepts connections from anywhere." );
 script_set_attribute(attribute:"description", value:
"The remote X11 server accepts connections from anywhere. An attacker
can connect to it to eavesdrop on the keyboard and mouse events of a
user on the remote host. It is even possible for an attacker to grab a
screenshot of the remote host or to display arbitrary programs. An
attacker can exploit this flaw to obtain the username and password of
a user on the remote host.");
 script_set_attribute(attribute:"solution", value:
"Restrict access to this port by using the 'xhost' command. If the X11
client/server facility is not used, disable TCP entirely.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'X11 No-Auth Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "1990/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/10");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("X.nasl");
  script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);

  exit(0);
}



for ( port = 6000 ; port < 6010 ; port ++ )
{
 if ( get_kb_item("x11/" + port + "/open") )
 {
   pci_report = 'The remote open X11 service on port ' + port + ' accepts cleartext logins.';
   set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
   security_hole(port);
 }
}
