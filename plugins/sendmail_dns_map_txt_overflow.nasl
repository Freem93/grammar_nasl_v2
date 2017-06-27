#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11232);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2012/06/25 21:34:34 $");

 script_cve_id("CVE-2002-0906");
 script_bugtraq_id(5122);
 script_osvdb_id(5056);

 script_name(english:"Sendmail Custom DNS Map TXT Query Overflow");
 script_summary(english:"Check sendmail version number");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on this host.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be 
vulnerable to a buffer overflow in its DNS handling code.

The owner of a malicious name server could use this flaw to cause a
denial of service and possibly to execute arbitrary code on this
host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail 8.12.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:".*sendmail +(SMI-.*|8\.([0-9]\.|10\.|11\.[0-6][^0-9]|12\.[0-4][^0-9])|[0-7]\.[0-9]*\.[0-9]*)", string:banner, icase:TRUE))
 	security_hole(port);
}
