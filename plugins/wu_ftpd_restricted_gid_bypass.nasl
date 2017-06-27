#
# (C) Tenable Network Security
#


include("compat.inc");


if (description)
{
 script_id(12098);
 script_cve_id("CVE-2004-0148");
 script_bugtraq_id(9832);
 script_osvdb_id(4160);
 script_xref(name:"RHSA", value:"2003:307-01");
 script_xref(name:"Secunia", value:"20168");
 script_xref(name:"Secunia", value:"11055");
 script_version("$Revision: 1.19 $");

 script_name(english:"WU-FTPD restricted-gid Directory Access Restriction Bypass");
 script_summary(english:"Checks the remote Wu-ftpd version");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an access restriction bypass vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host is running wu-ftpd 2.6.2 or older.

There is a bug in this version which may allow an attacker to bypass the
'restricted-gid' feature and gain unauthorized access to otherwise restricted
directories.

*** Nessus solely relied on the banner of the remote FTP server, so this might
*** be a false positive." );
 # https://web.archive.org/web/20060307170008/http://archives.neohapsis.com/archives/vendor/2004-q1/0073.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f341b41b"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/09");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");
include("backport.inc");
include("global_settings.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_backport_banner(banner:get_ftp_banner(port:port));
if ( ! banner ) exit(1, "Could not authenticate on the FTP server on port "+port+".");

if(egrep(pattern:"^220.*(wu|wuftpd)-((1\..*)|2\.([0-5]\..*|6\.[0-2]))", string:banner, icase:TRUE))
        security_hole(port);
