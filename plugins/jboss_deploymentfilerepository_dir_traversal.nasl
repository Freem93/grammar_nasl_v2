#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23843);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-5750");
  script_bugtraq_id(21219);
  script_osvdb_id(30767);

  script_name(english:"JBoss Application Server (jbossas) JMX Console DeploymentFileRepository Traversal Arbitrary File Manipulation");
  script_summary(english:"Tries to change the JMX Console DeploymentFileRepository's BaseDir");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java service that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be a version of JBoss that fails to
sanitize user-supplied input to the BaseDir parameter used by the
'DeploymentFileRepository' service of JMX Console before using it to
store or delete files.  An unauthenticated attacker may be able to
exploit this to alter files on the remote host subject to the
privileges of the JBoss user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/452830/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://issues.jboss.org/browse/JBAS-3861?_sscc=t" );
 script_set_attribute(attribute:"see_also", value:"http://wiki.jboss.org/wiki/Wiki.jsp?page=SecureTheJmxConsole" );
 script_set_attribute(attribute:"solution", value:
"Secure access to the JMX Console as described in the Wiki article
referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/27");
 script_cvs_date("$Date: 2016/05/16 14:02:52 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:jboss:jboss_application_server");
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:8080);

# Figure out the current BaseDir.
w = http_send_recv3(method:"GET",
  item:string(
    "/jmx-console/HtmlAdaptor?",
    "action=inspectMBean&",
    "name=jboss.admin%3Aservice%3DDeploymentFileRepository"
  ), 
  port:port
);
if (isnull(w)) exit(1, "The web server did not answer.");
res = w[2];

base = NULL;
pat = 'input type="text" name="BaseDir" value="([^"]+)"';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches)) 
  {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver))
    {
      base = ver[1];
      break;
    }
  }
}
if (isnull(base)) exit(0);


# Try to change it.
new_base = "../nessus";
postdata = string(
  "action=updateAttributes&",
  "name=jboss.admin%3Aservice%3DDeploymentFileRepository&",
   "BaseDir=", urlencode(str:new_base)
);
w = http_send_recv3(method:"POST", port:port,
  item: "/jmx-console/HtmlAdaptor",
  content_type: "application/x-www-form-urlencoded",
  data: postdata
);
if (isnull(w)) exit(1, "The web server did not answer.");
res = w[2];

# If our change went through...
if (string('input type="text" name="BaseDir" value="', new_base, '"') >< res)
{
  # There's a problem.
  security_hole(port);

  # Be nice and change it back?
  if (1)
  {
    postdata = string(
      "action=updateAttributes&",
      "name=jboss.admin%3Aservice%3DDeploymentFileRepository&",
       "BaseDir=", urlencode(str:base)
    );
    w = http_send_recv3(method:"POST", port:port,
      item: "/jmx-console/HtmlAdaptor", 
      content_type: "application/x-www-form-urlencoded",
      data: postdata
    );
  }
}
