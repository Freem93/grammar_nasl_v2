#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57918);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"EMC Celerra Control Station Default Credentials");
  script_summary(english:"Log with default credentials on EMC Celerra GUI");

  script_set_attribute(attribute:"synopsis",value:"The remote EMC Celerra control stations uses default credentials.");
  script_set_attribute(attribute:"description",value:
"The remote host appears to be an EMC Celerra control station.  Such
devices come with two well known default credentials which give full
control on the configuration.");
  script_set_attribute(attribute:"solution", value:"Change the passwords for the 'root' and 'nasadmin' accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

i = 0;
user[i] = "root";	pass[i++] = "nasadmin";
user[i] = "nasadmin";	pass[i++] = "nasadmin";

function test(port, user, pass)
{
  local_var	w, d;

  w = http_send_recv3(port: port, method: 'GET', item: '/Login', exit_on_fail: 1);
  # The full banner
  # d = 'banner=The+EMC%28C%29+version+of+Linux%28C%29%2C+used+as+the+operating+system+on+the+++%0D%0ACelerra%28TM%29+Control+Station%28s%29%2C+is+a+customized+version+of+Linux.++++%0D%0AThe+operating+system+is+copyrighted+and+licensed+pursuant+to+the+++%0D%0AGNU+General+Public+License+%28%22GPL%22%29%2C+a+copy+of+which+can+be+found+++%0D%0Ain+the+accompanying+documentation.++Please+read+the+GPL+carefully%2C+++%0D%0Abecause+by+using+the+Linux+operating+system+on+the+EMC+Celerra+you++%0D%0Aagree+to+the+terms+and+conditions+listed+therein.++%0D%0A++%0D%0AEXCEPT+FOR+ANY+WARRANTIES+WHICH+MAY+BE+PROVIDED+UNDER+THE+TERMS+AND+++%0D%0ACONDITIONS+OF+THE+APPLICABLE+WRITTEN+AGREEMENTS+BETWEEN+YOU+AND+EMC%2C+++%0D%0ATHE+SOFTWARE+PROGRAMS+ARE+PROVIDED+AND+LICENSED+%22AS+IS%22+WITHOUT+++%0D%0AWARRANTY+OF+ANY+KIND%2C+EITHER+EXPRESSED+OR+IMPLIED%2C+INCLUDING%2C+BUT+++%0D%0ANOT+LIMITED+TO%2C+THE+IMPLIED+MERCHANTABILITY+AND+FITNESS+FOR+A+++%0D%0APARTICULAR+PURPOSE.++In+no+event+will+EMC+Corporation+be+liable+to+++%0D%0Ayou+or+any+other+person+or+entity+for+%28a%29+incidental%2C+indirect%2C+++%0D%0Aspecial%2C+exemplary+or+consequential+damages+or+%28b%29+any+damages+++%0D%0Awhatsoever+resulting+from+the+loss+of+use%2C+data+or+profits%2C+++%0D%0Aarising+out+of+or+in+connection+with+the+agreements+between+you+++%0D%0Aand+EMC%2C+the+GPL%2C+or+your+use+of+this+software%2C+even+if+advised+++%0D%0Aof+the+possibility+of+such+damages.++%0D%0A++%0D%0A%22EMC%22+is+a+registered+trademark+of+EMC+Corporation%2C+and+%22Linux%22+++%0D%0Ais+a+registered+trademark+of+Linus+Torvalds.++%22Celerra%22+is+a+++%0D%0Atrademark+of+EMC.++%0D%0A++%0D%0AEMC+Celerra+Control+Station+Linux+release+2.0';

  d = 'banner=x';	# Works too!
  d += '&user='+user+'&password='+pass+'&Login=Login&request_uri=' +
    build_url(port: port, qs: '/') +
    '&client_type=gui';
  w = http_send_recv3(port: port, method: 'POST', item: '/Login', data: d, exit_on_fail: 1);
  if ('You have successfully authenticated.' >< w[2]) return 1;
  return 0;
}

port = get_http_port(default:443);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (report_paranoia < 2)
{
  res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);
  if (
    "<title>EMC Celerra Network Server</title>" >!< res &&
    ">Celerra Manager for" >!< res &&
    "You must enable JavaScript to run Celerra Manager." >!< res
  ) audit(AUDIT_WRONG_WEB_SERVER, port, "EMC Celerra Manager");
}

report = '';
for (i = 0; ! isnull(user[i]); i ++)
{
  if (test(port: port, user: user[i], pass: pass[i]))
  {
    report = report + user[i] + '\t' + pass[i] + '\n';
  }
}
if (report)
{
  if (report_verbosity > 0)
  {
    report = 
'\nIt was possible to log on the GUI with the following credentials :\n\n' +
report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'EMC Celerra Manager', build_url(port:port, qs:'/'));
