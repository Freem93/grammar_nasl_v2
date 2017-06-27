#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(14832);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/12/23 02:27:58 $");

 script_bugtraq_id(11262);
 script_osvdb_id(10374);
 script_cve_id("CVE-2004-0833");

 script_name(english:"Debian GNU/Linux Sendmail Default SASL Password");
 script_summary(english:"Checks SMTP authentication");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SMTP server has an account with a default password."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a Sendmail server with a default SASL
password of 'sendmail' / 'sendmailpwd'.  A spammer may use this account
to use the remote server as a spam relay for the internet."
 );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2004/dsa-554");
 script_set_attribute(attribute:"solution", value:"Disable this account or secure it with a strong password.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/28");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");

if ( ! defined_func("HMAC_MD5") ) exit(0);

user = "sendmail";
pass = "sendmailpwd";

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

banner = smtp_recv_banner(socket:soc);
if ( ! banner ) exit(0);
if ( "Sendmail" >!< banner ) exit(0);


send(socket:soc, data:'EHLO there\r\n');
r = smtp_recv_line(socket:soc);

send(socket:soc, data:'AUTH CRAM-MD5\r\n');
r = smtp_recv_line(socket:soc);
if ( !ereg(pattern:"^334 ", string:r) ) exit(0);

challenge = ereg_replace(pattern:"^334 (.*)", string:chomp(r), replace:"\1");
hash = HMAC_MD5(data:base64_decode(str:challenge), key:pass);
data = base64(str:user + " " + hexstr(hash));
send(socket:soc, data:data + '\r\n');
r = smtp_recv_line(socket:soc);
close(soc);
if ( ereg(pattern:"^235 ", string:r) ) security_hole(port);

