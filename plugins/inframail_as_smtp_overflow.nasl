#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18588);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2085");
  script_bugtraq_id(14077);
  script_osvdb_id(17607);

  script_name(english:"Inframail SMTP MAIL FROM Command Remote Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the SMTP server component of Inframail, a
commercial suite of network servers from Infradig Systems. 

According to its banner, the installed version of Inframail suffers
from a buffer overflow vulnerability that arises when the SMTP server
component processes a MAIL FROM command with an excessively long
argument (around 40960 bytes).  Successful exploitation will cause the
service to crash and may allow arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://reedarvin.thearvins.com/20050627-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jun/347" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Inframail 7.12 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/27");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for remote buffer overflow vulnerability in Inframail SMTP Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}


include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port:port);
if (banner && banner =~ "InfradigServers-MAIL \(([0-5]\..*|6.([0-2].*|3[0-7])) ")
  security_hole(port);
