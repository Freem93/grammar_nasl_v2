#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
# See the Nessus Scripts License for details
#
#
# Improved by John Lampe to see if XEXCH is an allowed verb


include("compat.inc");

if(description)
{
     script_id(11889);
     script_bugtraq_id(8838);
     script_osvdb_id(2674);
     script_xref(name:"MSFT", value:"MS03-046");
     script_cve_id("CVE-2003-0714");
     script_version("$Revision: 1.26 $");
     name["english"] = "Exchange XEXCH50 Remote Buffer Overflow";
     script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a buffer overflow or denial of
service attack." );
 script_set_attribute(attribute:"description", value:
"The remote mail server appears to be running a version of the
Microsoft Exchange SMTP service that is vulnerable to a flaw in the
XEXCH50 extended verb.  This flaw can be used to completely crash
Exchange 5.5 or to execute arbitrary code on Exchange 2000." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Oct/216" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-046" );
 script_set_attribute(attribute:"solution", value:
"Apply the one of the workarounds listed in the vendor's advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS03-046 Exchange 2000 XEXCH50 Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/15");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


    summary["english"] = "Tests to see if authentication is required for the XEXCH50 command";
    script_summary(english:summary["english"]);
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2003-2016 Digital Defense Inc.");
 
    family["english"] = "SMTP problems";
    script_family(english:family["english"]);
    
    script_dependencies("smtpserver_detect.nasl");
    script_require_ports("Services/smtp", 25);
    exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);


greeting = smtp_recv_banner(socket:soc);
debug_print("GREETING: ", greeting, "\n");

# look for the exchange banner, removing this may get us through some proxies
if (! egrep(string:greeting, pattern:"microsoft", icase:TRUE)) exit(0);

send(socket:soc, data: 'EHLO X\r\n');
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
debug_print("HELO: ", ok, "\n");
if("XEXCH50" >!< ok)exit(0);

send(socket:soc, data:'MAIL FROM: Administrator\r\n');
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
debug_print("MAIL: ", ok, "\n");

send(socket:soc, data:'RCPT TO: Administrator\r\n');
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
debug_print("RCPT: ", ok, "\n");

send(socket:soc, data:'XEXCH50 2 2\r\n');
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
debug_print("XEXCH50: ", ok, "\n");

if (egrep(string:ok, pattern:"^354 Send binary")) security_hole(port:port);

close(soc);
