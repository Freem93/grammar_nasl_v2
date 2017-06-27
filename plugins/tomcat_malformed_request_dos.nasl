#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17322);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2005-0808");
  script_bugtraq_id(12795);
  script_osvdb_id(14770);

  script_name(english:"Apache Tomcat AJP12 Protocol Malformed Packet Remote DoS");
  script_summary(english:"Checks for remote malformed request denial of service vulnerability in Apache Tomcat.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AJP connector is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Tomcat running on the
remote host is affected by a denial of service vulnerability due to a
failure to handle malformed input. By submitting a specially crafted
AJP12 request, an unauthenticated attacker can cause Tomcat to stop
responding. At present, details on the specific nature of such
requests are not generally known.");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JGEI-6A2LEF");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 5.x or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.0.0", severity:SECURITY_WARNING);
