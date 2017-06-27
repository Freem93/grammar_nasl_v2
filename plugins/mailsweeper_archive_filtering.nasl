#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14360);
 script_cve_id("CVE-2003-0922", "CVE-2003-0929", "CVE-2003-0930");
 script_bugtraq_id(10940);
 script_osvdb_id(8844);
 script_xref(name:"Secunia", value:"12301");
 script_version ("$Revision: 1.11 $");

 script_name(english:"MAILsweeper Archive File Filtering Bypass");
 script_summary(english:"Checks the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a security bypass vulnerability."
 );
 script_set_attribute( attribute:"description",    value:
"The remote host is running MAILsweeper - a content security solution
for SMTP.

According to its banner, the remote version of MAILsweeper may allow
an attacker to bypass the archive filtering settings of the remote
server by sending an archive in the format 7ZIP, ACE, ARC, BH, BZIP2,
HAP, IMG, PAK, RAR or ZOO." );
 # https://web.archive.org/web/20040818012256/http://www.corsaire.com/advisories/c030807-001.txt
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?932e2128"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MAILsweeper 4.3.15 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/13");
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_dependencie("sendmail_expn.nasl", "smtpserver_detect.nasl");
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
