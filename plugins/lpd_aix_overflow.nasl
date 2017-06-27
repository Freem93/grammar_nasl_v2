#
# (C) Tenable Network Security, Inc.
#

# This is a check for an OLD flaw

include("compat.inc");

if (description)
{
  script_id(11355);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2012/12/10 14:56:53 $");

  script_cve_id("CVE-2001-0671");
  script_osvdb_id(8008);
  script_xref(name:"CERT-CC", value:"CA-2001-30");

  script_name(english:"AIX lpd Multiple Functions Remote Overflow");
  script_summary(english:"Determines if lpd is running");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote buffer overflow
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote lpd daemon seems to be vulnerable to various buffer
overflows in the functions send_status(), kill_print() and 
chk_fhost().

*** Nessus solely relied on the version number of the remote
*** operating system to issue this warning, so this might be a
*** false positive");
 script_set_attribute(attribute:"solution", value:"Apply patches from your vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies("find_service1.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/lpd", 515);

  exit(0);
}



#
# The code starts here
#

os = get_kb_item("Host/OS");
if(!os)exit(0);
if("AIX" >!< os)exit(0);
if(!egrep(pattern:"AIX (5\.1|4\.3)", string:os))exit(0);

port = get_kb_item("Services/lpd");
if(!port)port = 515;

soc = open_sock_tcp(port);
if(!soc)exit(0);
else security_hole(port);
