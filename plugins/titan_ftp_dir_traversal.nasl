#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14659);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2012/09/24 21:50:54 $");

 script_osvdb_id(9396);
 script_xref(name:"Secunia", value:"8914");

 script_name(english:"Titan FTP Server quote stat Command Traversal Arbitrary Directory Listing");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"According to its banner, the version of Titan FTP Server running on
the remote host has a directory traversal vulnerability.  A remote
attacker could exploit this to view arbitrary files on the system."
 );
  # http://web.archive.org/web/20040223110816/http://dhgroup.org/bugs/adv21.txt
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f82b50d3"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:south_river_technologies:titan_ftp_server");
 script_end_attributes();
 
 summary["english"] = "Check Titan FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#the code

include ("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1);

if (egrep(pattern:"^220.*Titan FTP Server ([0-1]\.|2\.0[12][^0-9])", string:banner) ) 
	security_warning(port);

