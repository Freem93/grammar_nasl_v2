#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Delivered-To: moderator for bugtraq@securityfocus.com
# To: kerberos-announce@MIT.EDU
# Subject: MITKRB5-SA-2003-004: Cryptographic weaknesses in Kerberos v4 protocol
# Reply-To: krbdev@mit.edu
# From: Tom Yu <tlyu@mit.edu>

include("compat.inc");

if (description)
{
 script_id(11511);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2013/02/15 02:47:03 $");

 script_cve_id("CVE-2003-0138");
 script_bugtraq_id(7113);
 script_osvdb_id(4869);

 script_name(english:"Kerberos 4 Realm Principle Impersonation");
 script_summary(english:"Check for kerberos");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is using an authentication protocol with cryptographic
weaknesses.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerberos IV.

It has been demonstrated that the Kerberos IV protocol has inherent
design flaws that make it insecure to use.");
 script_set_attribute(attribute:"see_also", value:"http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-004-krb4.txt");
 script_set_attribute(attribute:"solution", value:
"Use Kerberos 5 instead.  If you run Kerberos 5 with Kerberos IV
backward compatibility, make sure you upgrade to version 1.3.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 exit(0);
}

include("audit.inc");

port = 750;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

req = raw_string(0x04, 0x02) + "nessus" + raw_string(0) + "NESSUS.ORG" + raw_string(0) + raw_string(0x3e, 0x8c, 0x25, 0xDC, 0x78) + "xkrbtgt" + raw_string(0) + "NESSUS.ORG" + raw_string(0);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);

# if there is a v4 implementation on the other end, make sure it hasn't been
# explicitly disabled by passing '-4 disable' to krb5kdc
if(r && ord(r[0]) == 4 && 'KRB will not handle v4 request' >!< r)security_hole(port:port, proto:"udp");
