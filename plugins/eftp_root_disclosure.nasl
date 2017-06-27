#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#
# GPL
#
# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com
#

include("compat.inc");

if(description)
{
  script_id(11093);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_bugtraq_id(3333);
  script_osvdb_id(51614);

  script_name(english:"EFTP Nonexistent File Request Installation Directory Disclosure");
  script_summary(english:"EFTP installation directory disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EFTP installed on the remote host reveals its
installation directory if sent a request for a nonexistent file.  An
authenticated attacker may leverage this flaw to gain more knowledge
about the affected host, such as its filesystem layout.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Sep/135" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2 or higher, as it has been reported to fix this
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/18");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login");
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

port = get_ftp_port(default: 21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if (!login)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  else login = "ftp";
}
if (!pass)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  else pass = "nessus@nessus.com";
}

soc = open_sock_tcp(port);
if(! soc) audit(AUDIT_SOCK_FAIL, port);

if (! ftp_authenticate(socket:soc, user:login, pass:pass))
  exit(1, "Cannot authenticate on port "+port+".");

for (i = 0; i < 2; i=i+1)
{
  req = strcat(cmd[i], ' nessus', rand(), '\r\n');
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  if (egrep(string:r, pattern:" '[A-Za-z]:\\'"))
  {
    security_warning(port);
    ftp_close(socket:soc);
    exit(0);
  }
}
ftp_close(socket:soc);
audit(AUDIT_LISTEN_NOT_VULN, 'EFTP', port);
