#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48255);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2010-2227", "CVE-2010-1157");
  script_bugtraq_id(41544);
  script_osvdb_id(64023, 66319);
  script_xref(name:"Secunia", value:"39574");

  script_name(english:"Apache Tomcat 6.0 < 6.0.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0 listening on the remote host is prior to 6.0.28. It is,
therefore, affected by multiple vulnerabilities:

  - If a web app is configured to use BASIC or DIGEST
    authentication and the 'realm-name' attribute is not
    configured in that web app's 'web.xml' file, the remote
    server's hostname or IP will be included in replies.
    (CVE-2010-1157)

  - An error exists in the handling of invalid values in
    the 'Transfer-Encoding' header of a request. An attacker
    can exploit this to cause a denial of service or to
    disclose sensitive information. (CVE-2010-2227)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/200");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.28");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/05");

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

tomcat_check_version(fixed:"6.0.28", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");
