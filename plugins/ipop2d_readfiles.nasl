#
# (C) Tenable Network Security, Inc.
#

# Theory :
#
# - log into the remote server
# - fold /etc/passwd
# - read 1
# - retr
#
# We only check the banner for this flaw
#


include("compat.inc");

if(description)
{
 script_id(10469);
 script_version ("$Revision: 1.24 $");
 script_bugtraq_id(1484);
 script_osvdb_id(368);
 
 script_name(english:"ipop2d fold Command Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote POP2 server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote pop2 server allows the reading of arbitrary
files for authenticated users, using the 'fold' command." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/14");
 script_cvs_date("$Date: 2015/01/14 15:43:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"checks if ipop2 allows the reading of any file");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");;
 script_require_ports("Services/pop2", 109);
 exit(0);
}


port = get_kb_item("Services/pop2");
if(!port)port = 109;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 
 #
 # Versions up to 4.55 are vulnerable
 #
 if(ereg(pattern:"\+ POP2 .* v4\.([0-4][0-9] .*|[5][0-5]) .*",
  	 string:b))security_warning(port);
}

