#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70414);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id(
    "CVE-2007-1036",
    "CVE-2012-0874",
    "CVE-2013-4810"
  );
  script_bugtraq_id(
    57552,
    62854,
    77037
  );
  script_osvdb_id(
    33744,
    89583,
    97153,
    98979,
    100829
  );
  script_xref(name:"CERT", value:"632656");
  script_xref(name:"EDB-ID", value:"16318");
  script_xref(name:"EDB-ID", value:"21080");
  script_xref(name:"EDB-ID", value:"28713");
  script_xref(name:"EDB-ID", value:"30211");
  script_xref(name:"ZDI", value:"ZDI-13-229");
  script_xref(name:"HP", value:"HPSBGN02952");
  script_xref(name:"HP", value:"SSRT101127");
  script_xref(name:"HP", value:"emr_na-c04041110");

  script_name(english:"Apache Tomcat / JBoss EJBInvokerServlet / JMXInvokerServlet Multiple Vulnerabilities");
  script_summary(english:"Attempts to access the servlets without credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The 'EBJInvokerServlet' and 'JMXInvokerServlet' servlets hosted on
the web server on the remote host are accessible to unauthenticated
users. The remote host is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists due to improper
    restriction of access to the console and web management
    interfaces. An unauthenticated, remote attacker can
    exploit this, via direct requests, to bypass
    authentication and gain administrative access.
    (CVE-2007-1036)

  - A remote code execution vulnerability exists due to the
    JMXInvokerHAServlet and EJBInvokerHAServlet invoker
    servlets not properly restricting access to profiles. An
    unauthenticated, remote attacker can exploit this to
    bypass authentication and invoke MBean methods,
    resulting in the execution of arbitrary code.
    (CVE-2012-0874)

  - A remote code execution vulnerability exists in the
    EJBInvokerServlet and JMXInvokerServlet servlets due to
    the ability to post a marshalled object. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to install arbitrary
    applications. Note that this issue is known to affect
    McAfee Web Reporter versions prior to or equal to
    version 5.2.1 as well as Symantec Workspace Streaming
    version 7.5.0.493 and possibly earlier.
    (CVE-2013-4810)");
  # https://www.redteam-pentesting.de/publications/2009-11-30-Whitepaper_Whos-the-JBoss-now_RedTeam-Pentesting_EN.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74979c27");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-13-229/");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_ejb.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Oct/126");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530241/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Dec/att-133/ESA-2013-094.txt");
  script_set_attribute(attribute:"solution", value:
"If using EMC Data Protection Advisor, either upgrade to version 6.x or
apply the workaround for 5.x. 

Otherwise, contact the vendor or remove any affected JBoss servlets.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-606");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:procurve_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:application_lifecycle_management");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:identity_driven_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_web_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_brms_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jboss:jboss_application_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:workspace_streaming");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9111, 8080, 9832);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Identify possible ports.
#
# - web servers.
ports = get_kb_list("Services/www");
if (isnull(ports)) ports = make_list();

# - ports for McAfee Web Reporter and Symantec Workspace Streaming.
foreach p (make_list(8080, 9111, 9832))
{
  if (service_is_unknown(port:p))  ports = add_port_in_list(list:ports, port:p);
}

# Check each port.
non_vuln = make_list();

foreach port (ports)
{
  vuln_urls = make_list();

  foreach page (make_list("/EJBInvokerServlet", "/JMXInvokerServlet"))
  {
    url = "/invoker" + page;
    res = http_send_recv3(
      method : "GET",
      item   : url,
      port   : port,
      fetch404     : TRUE
    );

    if (
      !isnull(res) &&
      "org.jboss.invocation.MarshalledValue" >< res[2] &&
      (
        'WWW-Authenticate: Basic realm="JBoss HTTP Invoker"' >!< res[1] ||
        "404 Not Found" >!< res[1]
      )
    ) vuln_urls = make_list(vuln_urls, build_url(qs:url, port:port));
  }

  if (max_index(vuln_urls) > 0)
  {
    if (max_index(vuln_urls) > 1) request = "URLs";
    else request = "URL";

    if (report_verbosity > 0)
    {
      report =
        '\n' +'Nessus was able to verify the issue exists using the following '+
        '\n' + request + ' :' +
        '\n' +
        '\n' + join(vuln_urls, sep:'\n') + '\n';

      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
  else non_vuln = make_list(non_vuln, port);
}

if (max_index(non_vuln) == 1) exit(0, "The web server tested on port " + port + " is not affected.");
else if (max_index(non_vuln) > 1)  exit(0, "None of the ports tested (" +join(non_vuln, sep:", ")+ ") contain web servers that are affected.");
