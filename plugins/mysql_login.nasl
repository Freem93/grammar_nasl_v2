#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91823);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/24 21:29:02 $");

  script_name(english:"MySQL Server Login Possible");
  script_summary(english:"Attempts to log into the remote MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to log into the remote database.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to log into the remote MySQL server using the supplied
credentials.");
  script_set_attribute(attribute:"see_also", value:"https://www.mysql.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}

include ("audit.inc");
include ("global_settings.inc");
include ("misc_func.inc");
include ("stream_func.inc");
include ("mysql_func.inc");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

global_var failure_details;
failure_details = '';

function test_login(port, username, password)
{
  local_var init_status, login_status, rows, err;

  # try and connect to mysql port
  init_status = mysql_init(
    port         : port,
    nocache      : TRUE);

  if(!init_status)
  {
    failure_details += 'Error establishing connection to MySQL server on port ' + port + '.';
    err = mysql_get_last_error();

    if(!isnull(err) && err['msg'] != '')
      failure_details += ' [ ' + err['msg'] + ' ]';

    failure_details += '\n';

    set_kb_item(name:"DB_Auth/MySQL/" + port + "/Failure", value:TRUE);
    set_kb_item(name:"DB_Auth/MySQL/" + port + "/FailureDetails", value:failure_details);

    exit(0, failure_details);
  }

  login_status = mysql_login(user:username, pass:password);
  if (login_status != 1)
  {
    failure_details += "Login failed with user '" + username + "'.";

    err = mysql_get_last_error();
    if(!isnull(err) && err['msg'] != '')
      failure_details += ' [ ' + err['msg'] + ' ]';
    failure_details += '\n';

    mysql_close();
    return FALSE;
  }

  # verify login by running 'select CURRENT_USER()'
  rows = mysql_query_41(sql:'select CURRENT_USER()');
  mysql_close();

  if (isnull(rows))
  {
    failure_details += "'select CURRENT_USER()' query failed with '" + username + "'." + '\n';
    return FALSE;
  }

  return TRUE;
}

creds = mysql_get_cred_combos_from_kb(port:port);

if(max_index(creds) == 0)
  audit(AUDIT_MISSING_CREDENTIALS, 'MySQL on port ' + port);

login_success = FALSE;

foreach idx (keys(creds))
{
  cred = creds[idx];

  username = cred["login"];
  password = cred["password"];

  if(test_login(port:port, username:username, password:password))
  {
    login_success = TRUE;
    break;
  }
}

if(!login_success)
{
  set_kb_item(name:"DB_Auth/MySQL/" + port + "/Failure", value:TRUE);
  set_kb_item(name:"DB_Auth/MySQL/" + port + "/FailureDetails", value:failure_details);
  exit(0, "Unable to authenticate to MySQL database on port " + port + ".");
}

set_kb_item(name:"DB_Auth/MySQL/" + port + "/Success", value:TRUE);

security_note(port:port, extra:"Credentialed checks have been enabled for MySQL server on port " + port + ".");
