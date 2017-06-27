#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if (description)
{
 script_id(17245);
 script_cve_id("CVE-2005-0483");
 script_bugtraq_id(12586);
 script_osvdb_id(14014, 14015, 14016);
 script_version("$Revision: 1.19 $");

 script_name(english:"glFTPd Multiple Script ZIP File Handling Arbitrary File / Directory Access");
 script_summary(english:"Checks the banner of the remote glFTPD server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is suceptible to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote glFTPD server fails to properly sanitize user-supplied
input to the 'sitenfo.sh', 'sitezpichk.sh', and 'siteziplist.sh'. An
attacker could exploit this flaw to disclose arbitrary files by
sending a spcially crafted request to the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/384" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to glFTPD 2.01 RC1 or later, as this reportedly fixes the
issues." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/18");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:glftpd:glftpd");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1, "No FTP banner on port "+port+".");

if ( egrep(pattern:"^220.* glftpd (1\.|2\.00_RC[1-7] )", string:banner) )
	security_warning(port);

