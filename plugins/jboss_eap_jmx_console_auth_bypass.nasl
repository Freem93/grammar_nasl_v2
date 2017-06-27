#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46181);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/11/14 17:31:36 $");

  script_cve_id("CVE-2010-1428");
  script_bugtraq_id(39710);
  script_osvdb_id(64172);
  script_xref(name:"Secunia", value:"39563");

  script_name(english:"JBoss Enterprise Application Platform '/web-console' Authentication Bypass");
  script_summary(english:"Tries to access ServerInfo.jsp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is configured insecurely, leaving it vulnerable
to security bypass attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of JBoss Enterprise Application Platform (EAP) running on
the remote host allows unauthenticated access to certain documents
under the '/web-console' directory.  This is due to a misconfiguration
in 'web.xml' that only requires authentication for GET and POST
requests.  Specifying a different command such as HEAD, DELETE or PUT
causes the default GET handler to be used without authentication.

A remote attacker can exploit this to obtain sensitive information
without providing authentication.

This version of JBoss EAP likely has other vulnerabilities, though
Nessus has not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7864017e");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mindedsecurity.com/MSA030409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=585899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1428.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to JBoss EAP version 4.2.0.CP09 / 4.3.0.CP08 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("jboss_jmx_console_accessible.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);

# Make sure this looks like jboss eap.
banner = get_http_banner(port:port);
if (isnull(banner)) exit(0, "Failed to get a banner from the web server on port "+port+".");

pat = '^X-Powered-By:.*JBoss';
if (!egrep(pattern:pat, string:banner))
  exit(0, "The web server on port "+port+" doesn't appear to be JBoss EAP.");

if (get_kb_item("JBoss/"+port+"/web-console"))
  exit(1, "The JBoss install on port "+port+" allows unauthenticated access to its /web-console directory.");

url = '/web-console/ServerInfo.jsp';
req = http_mk_put_req(port:port, item:url, data:'');
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

if (
  '<title>JBoss Management Console - Server Information</title>' >< res[2] &&
  'Base Location (local):' >< res[2]
)
{
  # Show the request used to get the page
  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report =
      '\nNessus retrieved '+build_url(qs:url, port:port)+
      '\nusing the following request :\n'+
      '\n'+crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+
      '\n'+req_str+
      crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+'\n';

    # If verbose, extract some potentially sensitive info
    if (report_verbosity > 1)
    {
      info = '';
      props = make_array(
        'OS', 'Operating system',
        'Version', 'JBoss EAP version',
        'Base Location \\(local\\)','JBoss EAP path',
        'JVM Version', 'Java version'
      );

      foreach prop (keys(props))
      {
        pattern = '<b>'+prop+': </b>([^<]+)</font>';
        match = eregmatch(string:res[2], pattern:pattern);
        if (match) info += '  ' + props[prop] + ' : ' + match[1] + '\n';
      }

      if (info != '')
        report += '\nThis page contains information such as :\n\n'+info;
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The JBoss EAP server on port '+port+' is not affected.');
