#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51958);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-3718");
  script_bugtraq_id(46177);
  script_osvdb_id(71558);
  script_xref(name:"Secunia", value:"43198");

  script_name(english:"Apache Tomcat 7.x < 7.0.4 SecurityManager Local Security Bypass");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.4. It is,
therefore, affected by a security bypass vulnerability due to an error
in the access restriction on a 'ServletContext' attribute which holds
the location of the work directory in Tomcat's SecurityManager. A
malicious web application can modify the location of the working
directory which then allows improper read and write access to
arbitrary files and directories in the context of Tomcat.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8da12114");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Feb/74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.4 or later. Alternatively,
undeploy untrusted third-party web applications.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");

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

tomcat_check_version(fixed:"7.0.4", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
