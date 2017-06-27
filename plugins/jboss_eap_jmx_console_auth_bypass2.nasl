#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53337);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2010-0738");
  script_bugtraq_id(39710);
  script_osvdb_id(64171);
  script_xref(name:"EDB-ID", value:"16316");
  script_xref(name:"EDB-ID", value:"16318");
  script_xref(name:"EDB-ID", value:"16319");
  script_xref(name:"EDB-ID", value:"17924");
  script_xref(name:"Secunia", value:"39563");

  script_name(english:"JBoss Enterprise Application Platform '/jmx-console' Authentication Bypass");
  script_summary(english:"Tries to access ServerInfo.jsp");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has an authentication bypass vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of JBoss Enterprise Application Platform (EAP) running on
the remote host allows unauthenticated access to documents under the
/jmx-console directory.  This is due to a misconfiguration in web.xml
which only requires authentication for GET and POST requests.
Specifying a different verb such as HEAD, DELETE, or PUT causes the
default GET handler to be used without authentication.

A remote, unauthenticated attacker could exploit this by deploying a
malicious .war file, resulting in arbitrary code execution.

This version of JBoss EAP likely has other vulnerabilities (refer to
Nessus plugins 33869 and 46181)."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7864017e");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mindedsecurity.com/MSA030409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=574105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0738.html"
  );
  # http://community.jboss.org/blogs/mjc/2011/10/20/statement-regarding-security-threat-to-jboss-application-server
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?debbe0e8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to JBoss EAP version 4.2.0.CP09 / 4.3.0.CP08 or later.

If a non-vulnerable version of the software is being used, remove
all <http-method> elements from the <security-constraint> section
of the appropriate web.xml."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-132");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

# make sure this looks like jboss eap unless paranoid
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if (
    !egrep(pattern:'^X-Powered-By:.*JBoss', string:banner) &&
    !egrep(pattern:'^Server: Apache-Coyote', string:banner) # HP BSM
  )
  {
    exit(0, "The web server on port "+port+" doesn't appear to be JBoss EAP.");
  }
}

if (get_kb_item("JBoss/"+port+"/jmx-console"))
  exit(1, "The JBoss install on port "+port+" allows unauthenticated access to its /jmx-console directory.");

url = '/jmx-console/checkJNDI.jsp';
res = http_send_recv3(method:'PUT', item:url, data:'', port:port, exit_on_fail:TRUE);

if (
  (
    'JNDI Check</title>' >< res[2] &&
    '<h1>JNDI Checking for host' >< res[2]
  ) ||
  (
    '<td>InitialContext properites</td>' >< res[2] &&
    '<td>jndi.properties locations</td>' >< res[2] &&
    '</td></tr><tr><td>jmx: org.jnp.interfaces.NamingContext:org.jnp.interfaces.NamingContext' >< res[2]
  ) ||
  (
    '</td></tr><tr><td>QueueConnectionFactory: org.jboss.naming.LinkRefPair' >< res[2] &&
    '</td></tr><tr><td>UUIDKeyGeneratorFactory: org.jboss.ejb.plugins.keygenerator.uuid.UUIDKeyGeneratorFactory' >< res[2]
  )
)
{
  # Show the request used to get the page
  if (report_verbosity > 0)
  {
    report =
      '\nNessus retrieved '+build_url(qs:url, port:port)+
      '\nwithout authentication by using the following request :\n'+
      '\n'+crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+
      '\n'+ http_last_sent_request() +
      crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+'\n\n'+
      'A portion of the HTML output is displayed below:\n'+
      '\n'+crap(data:"-", length:30)+' snip '+crap(data:"-", length:30)+
      '\n'+ beginning_of_response(resp:res[2], max_lines:20) + '\n' +
      crap(data:"-", length:30)+' snip '+crap(data:"-", length:30);

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The JBoss EAP server on port '+port+' is not affected.');
