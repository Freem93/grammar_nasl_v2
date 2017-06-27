#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46869);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2008-0128");
  script_bugtraq_id(27365);
  script_xref(name:"Secunia", value:"28552");
  script_osvdb_id(40853);

  script_name(english:"Apache Tomcat 6.x < 6.0.9 Information Disclosure");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.x listening on the remote host is prior to 6.0.9. It is,
therefore, affected by an information disclosure vulnerability.

If the remote Apache Tomcat install is configured to use the
SingleSignOn Valve, the JSESSIONIDSSO cookie does not have the
'secure' attribute set if authentication takes place over HTTPS. This
allows the JSESSIONIDSSO cookie to be sent to the same server when
HTTP content is requested.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/31");
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

tomcat_check_version(fixed:"6.0.9", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");
