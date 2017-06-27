#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17204);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_name(english: "News Server (NNTP) Anonymous Read / Write Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The NNTP server is open." );
 script_set_attribute(attribute:"description", value:
"The remote server seems open to remote users.  Some people prefer
open public NNTP servers to be able to read or post articles
anonymously.  Unwanted connections could waste your bandwidth or put
you into legal trouble if a malicious person were to use your server
to post abusive articles. 

Keep in mind that robots are harvesting such open servers on Internet,
so you cannot hope that you will stay hidden for long. 

** As it is very common to have IP based authentication, this might be 
** a false positive if the Nessus scanner is among the allowed source 
** addresses." );
 script_set_attribute(attribute:"solution", value:
"Enforce authentication or filter connections from outside." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Public NNTP server is open to outside");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("nntp_info.nasl");
 script_require_ports("Services/nntp", 119);

 exit(0);
}

#

include('global_settings.inc');
include('network_func.inc');

port = get_kb_item("Services/nntp");
if ( ! port ) port = 119;

# Unusable server
if (! get_kb_item('nntp/'+port+'/ready') ||
    ! get_kb_item('nntp/'+port+'/posting') ||
    ! get_kb_item('nntp/'+port+'/noauth') )
 exit(0);

# Only warn on private addresses. The server might be accessible
# through NAT, so we warn if we prefere FP
if (report_paranoia < 2 && is_private_addr()) exit(0);

security_warning(port: port);
set_kb_item(name: '/tmp/nntp/'+port+'/open', value: TRUE);
