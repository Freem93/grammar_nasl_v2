#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46868);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2007-1358", "CVE-2008-0128", "CVE-2008-4308");
  script_bugtraq_id(24524, 27365, 33913);
  script_osvdb_id(34881, 40853, 52407);
  script_xref(name:"Secunia", value:"28552");
  script_xref(name:"Secunia", value:"34057");

  script_name(english:"Apache Tomcat 5.x < 5.5.21 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 5.x listening on the remote host is prior to 5.5.21. It is,
therefore, affected by the following vulnerabilities :

  - The remote Apache Tomcat install is vulnerable to a
    cross-site scripting attack. The client supplied
    Accept-Language headers are not validated which allows
    an attacker to use a specially crafted URL to inject
    arbitrary HTML and script code into the user's browser.
    (CVE-2007-1358)

  - If the remote Apache Tomcat install is configured to use
    the SingleSignOn Valve, the JSESSIONIDSSO cookie does
    not have the 'secure' attribute set if authentication
    takes place over HTTPS. This allows the JSESSIONIDSSO
    cookie to be sent to the same server when HTTP content
    is requested. (CVE-2008-0128)

  - The remote Apache Tomcat install is affected by an
    information disclosure vulnerability. The doRead method
    fails to return the proper error code for certain error
    conditions, which can cause POST content to be sent to
    different, and improper, requests. (CVE-2008-4308)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=41217");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.21");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 5.5.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 79, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");

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

tomcat_check_version(fixed:"5.5.21", min:"5.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^5(\.5)?$");
