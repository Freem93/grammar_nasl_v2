#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72693);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2014-0050");
  script_bugtraq_id(65400);
  script_osvdb_id(102945);
  script_xref(name:"EDB-ID", value:"31615");

  script_name(english:"Apache Tomcat 8.0.x < 8.0.3 Content-Type DoS");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 8.0.x listening on the remote host is a version prior to 8.0.3.
It is, therefore, affected by a denial of service vulnerability due to
an error related to handling 'Content-Type' HTTP headers and multipart
requests such as file uploads.

Note that this error exists because of the bundled version of Apache
Commons FileUpload.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.3");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201402.mbox/%3C52F373FC.9030907@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?358ef049");
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
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

# Note that 8.0.2 contained the fix,
# but was never released.
tomcat_check_version(fixed:"8.0.2", min:"8.0.0", severity:SECURITY_WARNING, granularity_regex:"^8(\.0)?$");
