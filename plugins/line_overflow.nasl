#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11175);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 00:51:57 $");

 script_name(english:"Network Service Long Line Handling Remote DoS");
 script_summary(english:"Crashes a service by sending a too long line");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to kill the service by sending a single long text
line. This may indicate the presence of a buffer overflow. An attacker
may be able to use this flaw to crash your software or even execute
arbitrary code on your system.");
 script_set_attribute(attribute:"solution", value:"Contact your product vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  if (ACT_FLOOD) script_category(ACT_FLOOD);
  else		script_category(ACT_DENIAL);

  script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
  script_family(english:"Denial of Service");

  script_dependencie("find_service2.nasl");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

line = strcat(crap(512), '\r\n');

port = get_unknown_svc();
if (! port) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: line);
r = recv(socket:s, length:1); # Make sure data arrived
close(s);

for (i = 0; i < 3; i ++)
{
  sleep(i);
  s = open_sock_tcp(port);
  if (s) { close(s); exit(0); }
}
security_warning(port);
