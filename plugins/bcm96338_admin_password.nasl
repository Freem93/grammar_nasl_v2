#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35621);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");
 
  script_name(english:"Default Password (password) for 'admin' Account on Broadcom BCM96338 ADSL Router");
  script_summary(english:"Logs into the remote host with default credentials.");
     
  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Broadcom BCM96338 ADSL router, and its 'admin'
account uses the password 'password'.  An attacker may leverage this
issue to gain administrative access to the affected system.");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencie("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#

include('global_settings.inc');
include('byte_func.inc');
include('misc_func.inc');
include('telnet_func.inc');
include('telnet2_func.inc');
include('audit.inc');


port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var rcvdata, n, port, tictac;

n = 0;
function telnet_callback()
{
  local_var data, t;
  data = _FCT_ANON_ARGS[0];

  if (isnull(data))
  {
# The router is erratic. We sometimes need to press ENTER again after 
# we entered the password
    if (n == 2)
    {
      t = unixtime();
      if (t - tictac > 1)
      {
        telnet_write('\r\n');
        tictac = t;
        return -1;
       }
     }
    sleep(1);
    return -1; 
  }
  if (data[0] != '\0') rcvdata += data[0];
  if (n == 0)
  {
    if ("Login: " >< rcvdata)
    {
      telnet_write('admin\r\0');
      rcvdata = '';
      n ++;
    }
  }
  else if (n == 1)
  {
    if ("Password: " >< rcvdata)
    {
      telnet_write('password\r\0');
      rcvdata = '';
      n ++;
      tictac = unixtime();
    }
   }
   else if (n == 2)
   {
     if (' Main Menu' >< rcvdata)
     {
       set_kb_item(name: 'bcm96338/default_telnet_credential', value: TRUE);
       security_hole(port: port);
       exit(0);
     }
   }
  return 0;
}

# We don't want to spend 3 * read_timeout on every telnet server.
b = get_telnet_banner(port: port);
if (isnull(b)) audit(AUDIT_NO_BANNER, port);
if (! egrep(string: b, pattern: "BCM[0-9]+ ADSL Router"))
  exit(0, "The Telnet banner on port "+ port +" is not for a Broadcom BCM96338 ADSL Router.");

if (! telnet2_init(port: port, timeout: 3 * get_read_timeout()))
  audit(AUDIT_SVC_FAIL, "Telnet", port);
telnet_loop();
exit(0);
