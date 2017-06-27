#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57082);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2011-3375", "CVE-2011-3376");
  script_bugtraq_id(50603, 51442);
  script_osvdb_id(76944, 78331);

  script_name(english:"Apache Tomcat 7.x < 7.0.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.22. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists. Request
    information is cached in two objects, and these objects
    are not recycled at the same time. Further requests can
    obtain sensitive information if certain error conditions
    occur. (CVE-2011-3375)

  - The web server is not properly restricting access to
    the servlets that provide the functionality of the
    Manager application. This can allow untrusted web
    applications to access privileged internal functionality
    such as gathering information on running web
    applications and deploying additional web applications.
    (CVE-2011-3376)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1176588");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.22");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 7.0.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"7.0.22", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
