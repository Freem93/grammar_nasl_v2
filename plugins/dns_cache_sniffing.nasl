#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(12217);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/12/06 20:34:49 $");

 script_name(english:"DNS Server Cache Snooping Remote Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is vulnerable to cache snooping attacks." );
 script_set_attribute(attribute:"description", value:
"The remote DNS server responds to queries for third-party domains
that do not have the recursion bit set. 

This may allow a remote attacker to determine which domains have
recently been resolved via this name server, and therefore which hosts
have been recently visited. 

For instance, if an attacker was interested in whether your company
utilizes the online services of a particular financial institution,
they would be able to use this attack to build a statistical model
regarding company usage of that financial institution.  Of course, the
attack can also be used to find B2B partners, web-surfing patterns,
external mail servers, and more.

Note: If this is an internal DNS server not accessible to outside
networks, attacks would be limited to the internal network. This
may include employees, consultants and potentially users on
a guest network or WiFi connection if supported." );
 script_set_attribute(attribute:"see_also", value:"http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf");
 script_set_attribute(attribute:"solution", value: "Contact the vendor of the DNS software for a fix." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"DNS Cache Snooping");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("smtp_settings.nasl", "dns_server.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("dns_func.inc");

#
# The script code starts here
#

function rnd()
{
 return 1 + rand() % 254;
}

 
port = 53;
if(!get_udp_port_state(port))exit(0, "Port " + port + " is closed");


# domain to use
usersdomain = get_kb_item("Settings/third_party_domain");

if(!usersdomain) {
    domain[0] = string("www");      dsz[0] = strlen(domain[0]);
    domain[1] = string("google");   dsz[1] = strlen(domain[1]);
    domain[2] = string("com");      dsz[2] = strlen(domain[2]);
} else {
    domainsplit = split(usersdomain, sep:".");
    count = 0;
    foreach t (domainsplit) {
        t = ereg_replace(string:t, pattern:"\.", replace:"");
        domain[count] = t;
        dsz[count] = strlen(t);
        count++;
    }
}



# Step[0] let's try to insert this value into the cache 
req = raw_string(
rnd(),rnd(),0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];
req += raw_string(0x00,0x00,0x01,0x00,0x01);

soc = open_sock_udp(port);
if ( ! soc ) exit(1, "Could not open a UDP socket on port " + port);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if (strlen( r ) < 8 ) exit(0, "No DNS server listening on port " + port);
answers = (ord(r[6]) * 256) + ord(r[7]);
close(soc);
if ( answers == 0 ) exit(0, "The remote DNS server does not resolve outside host names");



# Step[1] let's create a non-recursive query for the same domain
#                | ID     |  flags  | Ques    | Answer  | Auth    | Addl    |
req = raw_string(rnd(),rnd(),0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00);

# domain to be queried 
for (t=0; domain[t]; t++) req = req + raw_string(dsz[t]) + domain[t];

#                     | Type    | Class   |
req += raw_string(0x00,0x00,0x01,0x00,0x01);





# Step[2] let's send our query and get back a reply
soc = open_sock_udp(port);
send(socket:soc, data:req);
r = recv(socket:soc, length:1024);
close (soc);


# Step[3] if we get a reply with an answer (i.e. not a pointer to where we might ourselves recurse)
# then we can flag this bug
if ( (r) && (strlen(r) > 8) ) {
    answers = (ord(r[6]) * 256) + ord(r[7]);
    #display(string("recvd ", answers, " answers from DNS server\n"));
    if (answers > 0)
    {
      if (report_verbosity > 0)
      {
        if (answers > 1) s = 's';
        else s = '';

        reply = dns_split(r);
        ips = NULL;
        for (i = 0; reply['an_rr_data_'+i+'_data']; i++)
        {
          ip = reply['an_rr_data_'+i+'_data'];      
          ips += int(ord(ip[0]))+"."+int(ord(ip[1]))+"."+int(ord(ip[2]))+"."+int(ord(ip[3])) + '\n';
        }
          
        report =
          '\nNessus sent a non-recursive query for ' + join(domain, sep:'.') +
          '\nand received '+answers+' answer'+s+' :\n\n' +
          ips;
        security_warning(port:port, proto:"udp", extra:report);
      }
      else security_warning(port:port, proto:"udp");
    }
} 
else exit(0, "The remote DNS server is not vulnerable to this problem");
