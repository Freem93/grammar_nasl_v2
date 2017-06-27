#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14585);
 script_version("$Revision: 1.17 $");

 script_bugtraq_id(3507);
 script_osvdb_id(51703);

 script_name(english:"WS_FTP Server STAT Command Remote Overflow");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has a  buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of WS_FTP running on the remote
host has a buffer overflow vulnerability.  Sending a 'STAT' command
followed by a very long argument results in a buffer overflow.  A
remote attacker could exploit this to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/31");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes(); 
 
 summary["english"] = "Check WS_FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"WS_FTP Server (1\.|2\.(0[^0-9.]|0\.[0-3][^0-9]))", string: banner))
	security_hole(port);
