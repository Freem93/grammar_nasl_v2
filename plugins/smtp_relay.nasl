#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10262);
 script_version ("$Revision: 1.57 $");
 script_cvs_date("$Date: 2017/05/09 15:19:41 $");

 script_cve_id(
  "CVE-1999-0512",
  "CVE-2002-1278",
  "CVE-2003-0285"
 );
 script_bugtraq_id(
  7580,
  8196,
  83209
 );
 script_osvdb_id(
  207,
  6066,
  7993
 );

 script_name(english:"MTA Open Mail Relaying Allowed");
 script_summary(english:"Checks if the remote mail server can be used to relay email.");
 
 script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote SMTP server allows mail relaying.
This issue allows any spammer to use your mail server to send their
mail to the world, thus flooding your network bandwidth and possibly
getting your mail server blacklisted.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your SMTP server so that it cannot be used as an
indiscriminate SMTP relay. Make sure that the server uses appropriate
access controls to limit the extent to which relaying is possible.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Email_spam");

 script_set_attribute(attribute:"vuln_publication_date", value:"1990/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');
include("smtp_func.inc");

if (is_private_addr()) exit(0, "This check is not effective when the target is on a private network.");

# can't perform this test on localhost
if(islocalhost())exit(0, "This check is not effective when the target is the localhost.");

# can't perform this test on the local net
if(islocalnet())exit(0, "This check is not effective when the target is on the local network.");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0, "The SMTP server on port "+port+" is broken.");


domain = get_kb_item("Settings/third_party_domain");
if (!domain) domain = 'example.edu';

 
function smtp_test_relay(tryauth)
{
 local_var crp, data, i, r, report, soc, trace;

 soc = open_sock_tcp(port);
 if (!soc) exit(1, "Can't open socket on port "+port+".");
 data = smtp_recv_banner(socket:soc);
 if (!data) 
 {
  close(soc);
  exit(1, "Failed to receive the banner from the SMTP server on port "+port+".");
 }
 trace = strcat('S : ', data);

 crp = string("HELO ", domain, "\r\n");
 trace = strcat(trace, 'C : ', crp);
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^2[0-9][0-9] .*", string:data)) return(0);
 trace = strcat(trace, 'S : ', data);

 if(tryauth)
 {
  crp = string("AUTH CRAM-MD5\r\n");
  trace = strcat(trace, 'C : ', crp);
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);
  trace = strcat(trace, 'S : ', data);

  crp = string("ZnJlZCA5ZTk1YWVlMDljNDBhZjJiODRhMGMyYjNiYmFlNzg2Z==\r\n");
  trace = strcat(trace, 'C : ', crp);
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);
  trace = strcat(trace, 'S : ', data);
 }

 crp = string("MAIL FROM: <test_1@", domain, ">\r\n");
 trace = strcat(trace, 'C : ', crp);
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);
 trace = strcat(trace, 'S : ', data);

 crp = string("RCPT TO: <test_2@", domain, ">\r\n");
 trace = strcat(trace, 'C : ', crp);
 send(socket:soc, data:crp);
 i = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:i))
 {
  trace = strcat(trace, 'S : ', i);
  crp = string("DATA\r\n");
  trace = strcat(trace, 'C : ', crp);
  send(socket:soc, data:crp);
  r = recv_line(socket:soc, length:1024);
  if(ereg(pattern:"^3[0-9][0-9] .*", string:r))
  {
   trace = strcat(trace, 'S : ', r);
   if (report_verbosity > 0)
   {
     trace = '\n  ' + str_replace(find:'\n', replace:'\n  ', string:trace);
     trace = chomp(trace);

     report = strcat(
       '\nHere is a trace of the traffic that demonstrates the issue :',
       '\n',
       trace
     );
     security_hole(port:port, extra:report);
   }
   else security_hole(port);
   set_kb_item(name:"SMTP/spam", value:TRUE);
   set_kb_item(name:"SMTP/" + port + "/spam", value:TRUE);
  }
 }
 close(soc);
}

smtp_test_relay(tryauth: 0);
smtp_test_relay(tryauth: 1);
