#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49702);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2002-0935");
  script_bugtraq_id(5067);
  script_osvdb_id(5051);

  script_name(english:"Apache Tomcat 4.x < 4.1.3 Denial of Service");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.3. It is,
therefore, affected by a denial of service vulnerability.

A malicious HTTP request can cause a request processing thread to
become unresponsive. Further requests of this type can cause all
request processing threads to become unresponsive.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.3");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/250");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 4.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/01");

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

tomcat_check_version(fixed:"4.1.3", min:"4.0.0", severity:SECURITY_WARNING, granularity_regex:"^4(\.1)?$");
