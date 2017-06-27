#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51975);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2010-3718", "CVE-2010-4172", "CVE-2011-0013");
  script_bugtraq_id(45015, 46174, 46177);
  script_osvdb_id(69456, 71557, 71558);
  script_xref(name:"Secunia", value:"42337");
  script_xref(name:"Secunia", value:"43194");

  script_name(english:"Apache Tomcat 6.0.x < 6.0.30 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0.x listening on the remote host is prior to 6.0.30. It is,
therefore, affected by multiple vulnerabilities :

  - An error in the access restriction on a 'ServletContext'
    attribute that holds the location of the work directory
    in Tomcat's SecurityManager. A malicious web application
    can modify the location of the working directory which
    then allows improper read and write access to arbitrary
    files and directories in the context of Tomcat.
    (CVE-2010-3718)

  - An input validation error exists in the Manager
    application in that it fails to filter the 'sort' and
    'orderBy' input parameters. (CVE-2010-4172)

  - An input validation error exists in the HTML manager
    application in that it fails to filter various input
    data before returning it to the browser. (CVE-2011-0013)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.30");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Nov/283");
  script_set_attribute(attribute:"solution", value:"Update Apache Tomcat to version 6.0.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");

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

tomcat_check_version(fixed:"6.0.30", min:"6.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^6(\.0)?$");
