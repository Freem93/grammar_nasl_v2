#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50526);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2003-0044", "CVE-2007-3384");
  script_bugtraq_id(6720, 25174);
  script_osvdb_id(9203, 9204, 39035);

  script_name(english:"Apache Tomcat 3.x < 3.3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 3.x listening on the remote host is prior to 3.3.2, It is,
therefore, affected by multiple vulnerabilities.

Unspecified cross-site scripting vulnerabilities exist in the 'ROOT'
and example applications shipped with this version of Tomcat.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-3.html#Fixed_in_Apache_Tomcat_3.3.2");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Aug/19");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 3.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

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

tomcat_check_version(fixed:"3.3.2", min:"3.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^3(\.3)?$");
