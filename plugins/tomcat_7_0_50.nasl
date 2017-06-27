#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72691);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2013-4322", "CVE-2013-4590");
  script_bugtraq_id(65767, 65768);
  script_osvdb_id(103706, 103707);

  script_name(english:"Apache Tomcat 7.0.x < 7.0.50 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.0.x listening on the remote host is prior to 7.0.50. It is,
therefore, affected by the following vulnerabilities :

  - The fix for CVE-2012-3544 was not complete and limits
    are not properly applied to chunk extensions and
    whitespaces in certain trailing headers. This error
    could allow denial of service attacks. (CVE-2013-4322)

  - The application allows XML External Entity (XXE)
    processing that could disclose sensitive information.
    (CVE-2013-4590)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.50");
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 7.0.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

# Note that 7.0.48 contained the fix,
# but was never released; neither was 7.0.49
tomcat_check_version(fixed:"7.0.48", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
