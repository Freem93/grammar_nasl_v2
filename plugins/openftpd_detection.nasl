#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14179);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2523");
 script_bugtraq_id(10830);
 script_osvdb_id(8261);

 script_name(english:"OpenFTPD SITE MSG FTP Command Format String");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server may be vulnerable to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenFTPD - an FTP server designed to help
file sharing (aka 'warez').  Some versions of this server are
vulnerable to a remote format string attack that could allow an
authenticated attacker to execute arbitrary code on the remote host. 

Note that Nessus did not actually check for this flaw, so this might
be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/21" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/361" );
 script_set_attribute(attribute:"solution", value:
"Disable the remote service." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/22");
 script_cvs_date("$Date: 2016/11/02 14:37:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines the presence of OpenFTPD");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports(21, "Services/ftp");
 exit(0);
}


include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

#
# We only check for the banner :
# - Most (all) OpenFTPD server do not accept anonymous connections
# - The use of OpenFTPD is not encouraged in a corporation environment
#
if ( egrep(pattern:"^220 OpenFTPD server", string:banner ) )
	security_warning(port);
