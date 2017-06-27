#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10481);  
  script_version("$Revision: 1.58 $");
  script_cvs_date("$Date: 2015/09/24 16:49:07 $");

  script_cve_id("CVE-2002-1809", "CVE-2004-1532");
  script_bugtraq_id(11704);
  script_osvdb_id(380, 16026, 101006);

  script_name(english:"MySQL Unpassworded Account Check");
  script_summary(english:"Checks for unpassword root / anonymous accounts");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server can be accessed without a password.");
  script_set_attribute(attribute:"description", value:
"It is possible to connect to the remote MySQL database server using an
unpassworded account.  This may allow an attacker to launch further
attacks against the database.");
  script_set_attribute(attribute:"see_also", value:
"http://dev.mysql.com/doc/refman/5.0/en/default-privileges.html");
  script_set_attribute(attribute:"solution", value:
"Disable or set a password for the affected account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/mysql", 3306);
  script_dependencies("find_service2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

function show_databases()
{
 local_var req, res, databases, loop;

 mysql_send_packet(data:mkbyte(3)+'show databases', num:0);
 res = mysql_recv_packet();

 databases = make_list();

 if (!isnull(res) && res['num'] == 1)
 {
  res = mysql_recv_packet();
  if (!isnull(res))
  {
   res = mysql_recv_packet();
   if (!isnull(res) && getbyte(blob:res['data'], pos:0) == 254)
   {
    loop = 1;
    while (loop)
    {
     res = mysql_recv_packet();
     if (!isnull(res) && getbyte(blob:res['data'], pos:0) != 254)
       databases = make_list(databases, substr(res['data'], 1, res['len']-1));
     else
       loop = 0;
    }
   }
  }
 }

 if (max_index(databases) > 0)
   return databases;
 else
  return NULL;
}

function current_user()
{
 local_var req, res, user;
 user = NULL;

 mysql_send_packet(data:mkbyte(3)+'select current_user()', num:0);
 res = mysql_recv_packet();

 if (!isnull(res) && res['num'] == 1)
 {
  res = mysql_recv_packet();
  if (!isnull(res))
  {
   res = mysql_recv_packet();
   if (!isnull(res) && getbyte(blob:res['data'], pos:0) == 254)
   {
     res = mysql_recv_packet();
     if (!isnull(res) && getbyte(blob:res['data'], pos:0) != 254)
     {
       user = substr(res['data'], 1, res['len']-1);
       res = mysql_recv_packet();
     }
   }
  }
 }

 return user;
}

## Main code ##

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

foreach name (make_list("root", "anonymous"))
{
 mysql_init(port:port, nocache:TRUE, exit_on_fail:TRUE);

 caps = mysql_get_caps();
 caps = caps & (0xFFFFFFFF - CLIENT_NO_SCHEMA);
 if (mysql_login(user:name, flags:caps) == 1)
 {
  # Check which user we authenticated as, not which user we _tried_
  # to authenticate as. This prevents erroneously flagging an
  # unpassworded root account when we actually authenticated as
  # an anonymous user
  user = current_user();

  if (!isnull(user))
  {
    user = split(user, sep:'@', keep:FALSE);
    if (user[0] == '')
      report = '\nThe anonymous account does not have a password.\n';
    else
      report = '\nThe \''+name+'\' account does not have a password.\n';
  }
  else report = '\nThe \''+name+'\' account does not have a password.\n';

  databases = show_databases();
  if (!isnull(databases))
  {
   info = "";
   foreach value (databases)
   {
    info += '  - '+value+'\n';
   }
   if (info)
   {
    report += '\nHere is the list of databases on the remote server :\n\n'+info;
    set_kb_item(name: 'MySQL/no_passwd/'+port, value: name);
   }
  }
  security_hole(port:port, extra:report);
  exit(0);
 }

 mysql_close();
}
audit(AUDIT_LISTEN_NOT_VULN, 'MySQL', port);

