#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44314);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902");
  script_bugtraq_id(37942, 37944, 37945);
  script_osvdb_id(62052, 62053, 62054);
  script_xref(name:"Secunia", value:"38316");
  script_xref(name:"Secunia", value:"38346");

  script_name(english:"Apache Tomcat WAR Deployment Multiple Vulnerabilities");
  script_summary(english:"Checks the Tomcat version number.");

  script_set_attribute(attribute:"synopsis", value:
"The web server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host is
running a version of Apache Tomcat that is affected by multiple
vulnerabilities :

  - When deploying WAR files, the WAR files are not checked
    for directory traversal attempts which could allow an
    attacker to create arbitrary content outside of the web
    root. (CVE-2009-2693)

  - By default, Tomcat automatically deploys any directories
    placed in a host's appBase.  This could lead to files
    which are normally protected by one or more security
    constraints being deployed without those security
    constraints. (CVE-2009-2901)

  - When deploying WAR files, the WAR file names are not
    checked for directory traversal attempts which could
    allow an attacker to caused the deletion of the current
    contents of the host's work directory. (CVE-2009-2902).

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509148/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/509150/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/509151/30/0/threaded");

  script_set_attribute(attribute:"solution", value:"Upgrade to Tomcat version 6.0.24 / 5.5.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

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

tomcat_check_version(fixed:make_list("6.0.24", "5.5.29"), severity:SECURITY_WARNING, granularity_regex:"^(6(\.0)?|5(\.5)?)$");
