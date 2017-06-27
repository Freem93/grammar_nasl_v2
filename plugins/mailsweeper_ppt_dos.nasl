#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11650);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2003-1477");
 script_bugtraq_id(10937, 7562);
 script_osvdb_id(8656);
 script_xref(name:"Secunia", value:"12277");

 script_name(english:"MAILsweeper for SMTP PowerPoint Document Processing DoS");
 script_summary(english:"Checks the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host is running MAILsweeper - a content security solution
for SMTP.

According to its banner, the remote version of MAILsweeper consumes
all available CPU resources when processing a malformed PowerPoint
file, causing the server to become non-responsive.  A remote attacker
could exploit this to cause a denial of service." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?70470982"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MAILsweeper 4.3.15 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/13");
 script_cvs_date("$Date: 2016/11/28 21:06:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);
if(egrep(string:banner, pattern:"^220 .* MAILsweeper ESMTP Receiver Version ([0-3]\.|4\.([0-2]\.|3\.([0-9]|1[0-4])[^0-9])).*$")) security_hole(port);
