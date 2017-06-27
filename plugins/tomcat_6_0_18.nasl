#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47578);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370");
  script_bugtraq_id(30494, 30496);
  script_osvdb_id(45905, 47462, 47463, 62511);
  script_xref(name:"Secunia", value:"30500");
  script_xref(name:"Secunia", value:"31379");

  script_name(english:"Apache Tomcat < 6.0.18 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is prior to 6.0.18. It is,
therefore, affected by multiple vulnerabilities :

  - The remote Apache Tomcat installation is affected by a
    cross-site scripting vulnerability in the
    HttpServletResponse.sendError method due to improper
    validation of user-supplied input to the 'message'
    argument. An attacker can exploit this to execute
    arbitrary script code in a user's browser session.
    (CVE-2008-1232)

  - A cross-site scripting vulnerability exists in the host
    manager application due to improper validation of
    user-supplied input to the 'hostname' parameter. An
    attacker can exploit this to execute arbitrary script
    code in a user's browser session. (CVE-2008-1947)

  - A traversal vulnerability exists when using a
    RequestDispatcher in combination with a servlet or JSP
    that allows a remote attacker to utilize a specially
    crafted request parameter to access protected web
    resources. (CVE-2008-2370)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.18");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"6.0.18", min:"6.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^6(\.0)?$");
