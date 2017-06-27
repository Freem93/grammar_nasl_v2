#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(18526);

 script_cve_id("CVE-2005-2006", "CVE-2006-0656");
 script_bugtraq_id(13985, 16571);
 script_osvdb_id(17402, 17403, 17404, 22992);

 script_version("$Revision: 1.19 $");
 
 script_name(english:"JBoss org.jboss.web.WebServer Class Multiple Vulnerabilities (Source Disc, ID)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote JBoss server is vulnerable to an information disclosure
flaw that could allow an attacker to retrieve the physical path of the
server installation, its security policy, or to guess its exact
version number.  An attacker may use this flaw to gain more
information about the remote configuration." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111911095424496&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10104" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JBoss 3.2.8 or 4.0.3.  Or edit JBoss' 'jboss-service.xml'
configuration file, set 'DownloadServerClasses' to 'false', and
restart the server." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"RedHat JBoss File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/17");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:jboss:jboss");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
 summary["english"] = "Attempts to read security policy of a remote JBoss server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8083, 50013);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = get_kb_list("Services/www");
ports = add_port_in_list(list:ports, port:8083);
ports = add_port_in_list(list:ports, port:50013);

foreach port (ports) {
  if (get_port_state(port)) {
    r = http_send_recv3(port:port, method: 'GET', item: "%.");

    if (! isnull(r) && ereg(pattern:"^HTTP/.* 400 (/|[A-Za-z]:\\)", string:r[0])) {
      file = "server.policy";
      r = http_send_recv3(method: 'GET', item:"%"+file, port:port);
      if (!isnull(r) && "JBoss Security Policy" >< r[2]) {
        report = string(
          "Here are the contents of the file '", file, "' that\n",
          "Nessus was able to read from the remote host :\n",
          "\n",
          r[2]
        );

        security_warning(port:port, extra:report);
      }
    }
  }
}
