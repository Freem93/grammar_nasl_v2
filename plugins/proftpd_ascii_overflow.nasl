#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11849);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2011/12/05 17:40:21 $");

 script_cve_id("CVE-2003-0831");
 script_bugtraq_id(8679);
 script_osvdb_id(10769);

 script_name(english:"ProFTPD File Transfer Newline Character Overflow");
 script_summary(english:"Checks the remote ProFTPD version");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ProFTPD which seems to be 
vulnerable to a buffer overflow when a user downloads a malformed ASCII
file.

An attacker with upload privileges on this host may abuse this flaw to 
gain a root shell on this host.

*** The author of ProFTPD did not increase the version number
*** of his product when fixing this issue, so it might be false
*** positive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD 1.2.9 when available or to 1.2.8p");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");		  

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

#
# The script code starts here : 
#

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1);


if(egrep(pattern:"^220 ProFTPD 1\.([01]\..*|2\.[0-6][^0-9]|2\.[7-8][^0-9]|2\.9rc[0-2])", string:banner))
	security_hole(port);
