#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10137);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-1999-0846");
 script_bugtraq_id(8554);
 script_osvdb_id(109);

 script_name(english:"MDaemon Connection Saturation Remote DoS");
 script_summary(english:"Crashes the remote MTA");

 script_set_attribute(attribute:"synopsis", value:"The remote SMTP server has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote version of MDaemon by establishing
a large number of connections to it. A remote attacker can exploit
this to cause a denial of service.

Note that due to the nature of this vulnerability, Nessus cannot be
100% positive on the effectiveness of this check. As a result, this
report might be a false positive.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/372");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);

 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

 i = 0;
 ref_soc = open_sock_tcp(port);
 if ( ! ref_soc ) exit(0);
 banner = smtp_recv_line(socket:ref_soc);

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 while(TRUE)
 {
  soc = open_sock_tcp(port);
  if(!soc){
  	sleep(5);
	soc2 = open_sock_tcp(port);
	if(!soc2){
	 send(socket:ref_soc, data:'HELP\r\n');
         out = smtp_recv_line(socket:ref_soc);
         if ( ! out ) security_warning(port);
         }
	else close(soc2);
        close(ref_soc);
	exit(0);
    }
  if( i > 400)
  {
        close(ref_soc);
 	exit(0);
  }
  i = i + 1;
 }

