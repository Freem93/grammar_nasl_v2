#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39479);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2009-0783");
  script_bugtraq_id(35416);
  script_osvdb_id(55056);
  script_xref(name:"Secunia", value:"35326");
  script_xref(name:"Secunia", value:"35344");

  script_name(english:"Apache Tomcat Cross-Application File Manipulation");
  script_summary(english:"Checks the Tomcat version number.");

  script_set_attribute(attribute:"synopsis", value:
"The web server running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host is
running a vulnerable version of Apache Tomcat. Affected versions
permit a web application to replace the XML parser used to process the
XML and TLD files of other applications. This could allow a malicious
web app to read or modify 'web.xml', 'context.xml', or TLD files of
arbitrary web applications.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=29936");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504090");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to versions 7.0.19 / 6.0.20 / 5.5.28 / 4.1.40 or later.
Alternatively, apply the patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("7.0.19", "6.0.20", "5.5.28", "4.1.40"), severity:SECURITY_WARNING, granularity_regex:"^(7(\.0)?|6(\.0)?|5(\.5)?|4(\.1)?)$");
