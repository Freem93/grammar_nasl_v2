#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47749);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-3718", "CVE-2010-2227", "CVE-2010-1157");
  script_bugtraq_id(39635, 41544, 46177);
  script_osvdb_id(64023, 66319, 71558);
  script_xref(name:"Secunia", value:"39574");
  script_xref(name:"Secunia", value:"43198");

  script_name(english:"Apache Tomcat 5.5.x < 5.5.30");
  script_summary(english:"Checks Apache Tomcat Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server listening on the remote host is 5.5.x prior to 5.5.30. It is,
therefore, affected by multiple vulnerabilities :

  - An error in the access restriction on a 'ServletContext'
    attribute which holds the location of the work
    directory in Tomcat's SecurityManager. A remote attacker
    may be able to modify the location of the working
    directory which then allows improper read and write
    access to arbitrary files and directories in the context
    of Tomcat.(CVE-2010-3718)

  - An error exists in the handling of the
    'Transfer-Encoding' header of a client request. This
    error affects buffer recycling and may lead to the
    disclosure of sensitive information or allow a denial
    of service attack to be successful. (CVE-2010-2227)

  - An error exists in the handling of the '<realm-name>'
    element in a web application's web.xml file. If the
    element is missing from the web.xml file and the
    application is using BASIC or DIGEST authentication,
    Tomcat will include the server's hostname or IP address
    in the 'WWW-Authenticate' header of the response.
    (CVE-2010-1157)

Note that Nessus did not actually test for the flaws but instead has
relied on the version in Tomcat's banner or error page so this may be
a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.30");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/200");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?809a4670");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Feb/74");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tomcat version 5.5.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.5.30", min:"5.5.0", severity:SECURITY_WARNING, granularity_regex:"^5(\.5)?$");
