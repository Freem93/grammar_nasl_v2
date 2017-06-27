#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(17593);
 script_cve_id("CVE-2005-0850", "CVE-2005-0851");
 script_bugtraq_id(12865);
 script_osvdb_id(14928, 14929);
 script_xref(name:"Secunia", value:"14664");
 script_version("$Revision: 1.14 $");

 script_name(english:"FileZilla FTP Server Multiple DoS");
 script_summary(english:"Determines the presence of FileZilla");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has multiple denial of service vulnerabilities."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of FileZilla server with the
following denial of service vulnerabilities :

  - Requesting a file containing the reserved name of a DOS
    device (e.g. CON, NUL, COM1, etc.) can cause the
    server to freeze.

  - Downloading a file or directory listing with MODE Z
    enabled (zlib compression) can cause an infinite loop." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sourceforge.net/project/shownotes.php?release_id=314473"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to FileZilla Server 0.9.6 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/22");
 script_cvs_date("$Date: 2014/07/11 18:33:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 
 script_dependencies("ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

if(egrep(pattern:"^220.*FileZilla Server version 0\.([0-8]\.|9\.[0-5][^0-9])", string:banner))
        security_hole(port);

