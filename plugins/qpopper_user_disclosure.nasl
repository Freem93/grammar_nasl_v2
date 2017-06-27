#
# This script is based on Thomas Reinke's qpopper2.nasl
# Modified by Scott Shebby scotts@scanalert.com
#

# Changes by Tenable:
# - Revised plugin title, output formatting (8/6/09)


include("compat.inc");

if(description)
{
 script_id(12279);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7110);
 script_osvdb_id(2184);

 script_name(english:"Qpopper Authentication Timing Response Account Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an account enumeration
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server appears to be running a version of Qpopper that is
older than 4.0.6.

Versions older than 4.0.6 are vulnerable to a bug where remote 
attackers can enumerate valid usernames based on server responses 
during the authentication process." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Qpopper Username Information Disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Scott Shebby");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner){
    if(get_port_state(port)){
        soc = open_sock_tcp(port);
        if(!soc)exit(0);
        banner = recv_line(socket:soc, length:4096);
    }
}

if(banner){
    if(ereg(pattern:".*Qpopper.*version ([0-3]\..*|4\.0\.[0-5][^0-9]).*", string:banner, icase:TRUE)){
        security_warning(port);
    }
}
