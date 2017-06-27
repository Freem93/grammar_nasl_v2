
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11407);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2011/12/09 22:58:49 $");

 script_cve_id("CVE-2001-0318");
 script_bugtraq_id(6781);
 script_osvdb_id(5705);
 
 script_name(english:"ProFTPD 1.2.0rc2 Malformed cwd Command Format String");
 script_summary(english:"Checks if the version of the remote proftpd");
             
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to run arbitrary code on this server.");
 script_set_attribute(attribute:"description", value:
"The remote ProFTPd server is as old or older than 1.2.0rc2

There is a very hard to exploit format string vulnerability in
this version that could allow an attacker to execute arbitrary
code on this host.

The vulnerability is believed to be nearly impossible to exploit
though.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
                 
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_ftp_port(default: 21);

# get_ftp_banner will return NULL if the server is fake.
banner = get_ftp_banner(port:port);
if (! banner) exit(1);

if ( egrep(pattern:"^220 ProFTPD 1\.[0-1]\..*", string:banner) ||
     egrep(pattern:"^220 ProFTPD 1\.2\.0(pre.*|rc[1-2][^0-9])", string:banner))
  security_hole(port);
