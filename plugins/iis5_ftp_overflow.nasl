#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40825);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_cve_id("CVE-2009-3023");
 script_bugtraq_id(36189);
 script_osvdb_id(57589);
 script_xref(name:"CERT", value:"276653");
 script_xref(name:"IAVB", value:"2009-B-0052");
 script_xref(name:"MSFT", value:"MS09-053");

 script_name(english:"MS09-053: Microsoft IIS FTPd NLST Command Remote Buffer Overflow (975191) (uncredentialed check)");
 script_summary(english:"Checks the version of IIS FTP");

 script_set_attribute(attribute:"synopsis", value:
"The remote anonymous FTP server seems vulnerable to an arbitrary code
execution attack.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server allows anonymous users to create directories in
one or more locations.

The remote version of this server is vulnerable to a buffer overflow
attack in the NLST command which, when coupled with the ability to
create arbitrary directories, may allow an attacker to execute
arbitrary commands on the remote Windows host with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-053");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 5.0, 5.1, 6.0, and
7.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS09-053 Microsoft IIS FTP Server NLST Response Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);
 script_set_attribute(attribute:"see_also", value:"http://securityvulns.com/files/iiz5.pl");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/975191");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("ftp_anonymous.nasl", "ftp_writeable_directories.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/tested_writeable_dir");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include('ftp_func.inc');

exit(0);


port = get_ftp_port(default: 21);
dir = get_kb_item("ftp/"+port+"/tested_writeable_dir");
if (! dir) exit(0, "No writeable dir found on port"+port+".");

banner = get_ftp_banner(port:port);
if ( isnull(banner) ) exit(1, "Could not retrieve the FTP server's banner");
if ( egrep(pattern:"^22.* Microsoft FTP Service \(Version 5\.[01]\)", string:banner) )
	security_hole(port:port, extra:'The directory ' + dir + ' could be used to exploit the server');
else if ( !egrep(pattern:"^22.* Microsoft FTP Service \(Version ", string:banner )) {
    soc = open_sock_tcp(port);
    if ( ! soc ) exit(1, "Could not connect to the remote FTP server on port "+port+".");
    banner = ftp_recv_line(socket:soc);
    if ( ! ftp_authenticate(user:"anonymous", pass:"joe@", socket:soc) )
     exit(1, "Could not log into the remote FTP server on port "+port+".");
    send(socket:soc, data:'STAT\r\n');
    r = ftp_recv_line(socket:soc);
    if ( "Microsoft Windows NT FTP Server status" >< r &&
	 ("Version 5.0" >< r || "Version 5.1" >< r ) ) security_hole(port:port, extra:'The directory ' + dir + ' could be used to exploit the server.');
 }
