#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(39329);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2014/05/29 04:24:09 $");
 script_name(english: "News Server (NNTP) Anonymous Read Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote NNTP server allows anyone to access it." );
 script_set_attribute(attribute:"description", value:
"The remote NNTP server seems to be open to outsiders.  Some people
like open NNTP servers as they allow one to read Usenet news articles
anonymously.  Unwanted connections could waste your bandwidth. 

Note that it is very common for NNTP servers to use IP-based
authentication so this may be a false positive if the Nessus scanner
is among the allowed source addresses.");
 script_set_attribute(attribute:"solution", value:
"Enforce authentication or filter connections from outside." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Public NNTP server is readable from outside");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("nntp_info.nasl", "open_nntp_server.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#

include('global_settings.inc');
include('network_func.inc');

# Only warn on private addresses. The server might be accessible
# through NAT, so we warn if we prefer FP
if (report_paranoia < 2 && is_private_addr()) exit(0);

port = get_kb_item("Services/nntp");
if ( ! port ) port = 119;

# Unusable server
if (! get_kb_item('nntp/'+port+'/ready') ||
    ! get_kb_item('nntp/'+port+'/noauth') )
 exit(0);

# open_nntp_server already issued a warning
if (get_kb_item('/tmp/nntp/'+port+'/open')) exit(0);

security_note(port: port);
