#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18402);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1815");
  script_bugtraq_id(13790);
  script_osvdb_id(16956, 16957);

  script_name(english:"Hummingbird InetD FTP Component (ftpdw.exe) Command Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the ftpd daemon installed on the remote host
is from the Hummingbird Connectivity suite and suffers from a buffer
overflow vulnerability. An attacker can crash the daemon and possibly
execute arbitrary code remotely within the context of the affected
service." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83df6392" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Hummingbird Connectivity 10 SP5 LPD Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/18");
 script_cvs_date("$Date: 2014/05/21 20:41:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  script_summary(english:"Checks for buffer overflow vulnerability in Hummingbird ftpd");
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_ftp_port(default: 21);


# Use a banner check; it's not configurable.
banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(string:banner, pattern:"^220[- ] .+HCLFTPD\) Version ([0-9]\.|10\.0\.0\.0)\)")
) security_hole(port);

