#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50475);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2003-0866", "CVE-2002-2006");
  script_bugtraq_id(4575, 5542, 8824);
  script_osvdb_id(849, 8772, 9695);

  script_name(english:"Apache Tomcat 4.x < 4.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.0. It is,
therefore, affected by multiple vulnerabilities :

  - An error exists in the handling of malformed packets
    that can cause the processing thread to become
    unresponsive. A sequence of such requests can cause all
    threads to become unresponsive. (CVE-2003-0866)

  - Two example servlets, 'snoop' and a troubleshooting
    servlet, disclose the Apache Tomcat installation path.
    (CVE-2002-2006)

  - It has also been reported that this version of Tomcat
    is affected by a cross-site scripting vulnerability.
    The contents of a request URL are not sanitized before
    being returned to the browser should an error occur.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.0");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/322");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 4.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/04");

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

tomcat_check_version(fixed:"4.1.0", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4$");
