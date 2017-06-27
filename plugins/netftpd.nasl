#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(18142);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2005-1323");
 script_bugtraq_id(13396);
 script_osvdb_id(15865);

 script_name(english:"Intersoft NetTerm Netftpd USER Command Remote Overflow");
 script_summary(english:"Checks for NetTerm Netftpd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote server is running NetTerm Netftpd server.

There is a buffer overflow condition in the remote version of this
software. An attacker may exploit this flaw to execute arbitrary code
on the remote host with the privileges of the FTP server."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to a version of NetTerm greater than 5.1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NetTerm NetFTPD USER Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/396959'
  );
  
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securenetterm.com/html/what_s_new.html'
    );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/26");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:intersoft:netterm");
  script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

ftpbanner = get_ftp_banner(port:port);
if (! ftpbanner ) exit(1);
if ( egrep(pattern:"^220 NetTerm FTP server ready", string:ftpbanner) )
	security_hole(port);
