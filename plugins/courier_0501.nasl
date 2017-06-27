#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18620);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-2151");
  script_bugtraq_id(14135);
  script_osvdb_id(17718);
 
  script_name(english:"Courier Mail Server < 0.50.1 DNS SPF Record Lookup Failure Memory Corruption DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Courier Mail Server, an open source mail
server for Linux and Unix. 

According to its banner, the installed version of Courier is prone to
a remote denial of service vulnerability triggered when doing Sender
Policy Framework (SPF) data lookups.  To exploit this flaw, an
attacker would need to control a DNS server and return malicious SPF
records in response to queries from the affected application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Courier version 0.50.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/02");
 script_cvs_date("$Date: 2013/01/07 22:52:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:double_precision_incorporated:courier_mail_server");
script_end_attributes();

  script_summary(english:"Checks version of Courier Mail Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

# Check the version number in the banner -- versions < 0.50.1 are vulnerable.
banner = get_smtp_banner(port:port);
if (banner && banner =~ "Courier 0\.([0-4][0-9]\.|50\.0[^0-9]*)")
  security_note(port); 
