#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57336);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2011-3372");
  script_bugtraq_id(49949);
  script_osvdb_id(76057);

  script_name(english:"Cyrus IMAPd NNTP AUTHINFO USER Command Parsing Authentication Bypass");
  script_summary(english:"Tries to bypass authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NNTP server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NNTP server contains a logic error that causes clients
that send only a username, neglecting to send a password, to be
treated as authenticated.  This may permit an unauthenticated, remote
attacker to view and post to restricted newsgroups, impersonating
other users in the process.");

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-68/");

  script_set_attribute(attribute:"solution", value:"Upgrade Cyrus IMAPd to version 2.4.12 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cmu:cyrus_imap_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("nntp_anonymous.nasl");
  script_require_ports("Services/nntp");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("nntp_func.inc");

# Find the port the NNTP server runs on.
port = get_service(svc:"nntp", exit_on_fail:TRUE);

# The fix for this issue updates conditionals that look like this:
#   ... (nntp_userid || allowanonymous)) ...
# to look like this:
#   ... (nntp_authstate || allowanonymous) ...
# This means that we can only check whether the vulnerability is
# present if the server doesn't support ANONYMOUS authentication.
anonymous = get_kb_item_or_exit("nntp/" + port + "/anonymous");
if (anonymous) exit(0, "The NNTP server listening on port " + port + " permits ANONYMOUS authentication, and therefore cannot be checked.");

# Connect to the NNTP server. The initial banner is delayed several
# seconds before sending, by default, so we'll up the timeout.
soc = open_sock_tcp(port, timeout:get_read_timeout() + 5);
if (!soc) exit(1, "TCP connection failed to port " + port + ".");

# Receive the banner.
res = nntp_recv(socket:soc, code:200, exit_on_fail:TRUE);

# Ensure that this is actually Cyrus.
if ("Cyrus NNTP" >!< res["status"]) 
  exit(0, "The NNTP server listening on port " + port + " does not appear to be Cyrus.");

# Negotiate StartTLS if this port supports it, since by default Cyrus
# won't accept AUTHINFO USER commands over an unencrypted channel.
if (get_kb_item("nntp/" + port + "/starttls"))
{
  soc = nntp_starttls(socket:soc, encaps:ENCAPS_TLSv1);
  if (!soc) exit(1, "StartTLS command failed on NNTP server listening on port " + port + ".");
}

# Begin user authentication.
nntp_cmd(socket:soc, cmd:"AUTHINFO USER nessus" + rand(), code:381, exit_on_fail:TRUE);

# Ask for help, so we know which commands are available in our current
# state.
res = nntp_cmd(socket:soc, cmd:"HELP", code:100, exit_on_fail:TRUE);

# These are the commands that, in the vulnerable version, is
# available to us after presenting only a username. If anonymous users
# were permitted, which we've ensured is not the case, we'd also see
# these commands in the fixed version.
cmds = make_list(
  "ARTICLE", "BODY", "DATE", "GROUP", "HEADER", "LAST",
  "LIST HEADERS", "LIST NEWSGROUPS", "LIST OVERVIEW.FMT", "LISTGROUP",
  "NEWNEWS", "NEXT", "OVER", "POST", "XPAT"
);

# Find all of the commands that we have access to that we shouldn't.
auth_cmds = make_list();
foreach cmd (cmds)
{
  if (egrep(string:res["body"], pattern:"^\t" + cmd))
    auth_cmds = make_list(auth_cmds, cmd);
}

if (max_index(auth_cmds) == 0)
  exit(0, "The NNTP server listening on port " + port + " does not appear to be affected.");

if (report_verbosity > 0)
{
  report =
    '\nThe following commands are available to clients that provide a username,' +
    '\nbut neglect to provide a password, bypassing authentication :' +
    '\n' +
    '\n  ' + join(auth_cmds, sep:'\n  ') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
