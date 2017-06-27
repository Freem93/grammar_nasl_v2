#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17726);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2005-2090", "CVE-2007-0450", "CVE-2007-1358");
  script_bugtraq_id(13873, 22960, 24524);
  script_osvdb_id(34769, 34881, 43452);

  script_name(english:"Apache Tomcat 4.x < 4.1.36 Multiple Vulnerabilities");
  script_summary(english:"Checks Apache Tomcat Version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.36. It is,
therefore, affected by the following vulnerabilities :

  - Requests containing multiple 'content-length' headers
    are not rejected as invalid. This error can allow
    web-cache poisoning, cross-site scripting attacks and
    information disclosure. (CVE-2005-2090)

  - An input sanitization error exists that can allow
    disclosure of sensitive information via directory
    traversal. This vulnerability is exposed when the
    server is configured to use the 'Proxy' module.
    (CVE-2007-0450)

  - 'Accept-Language' headers are not validated properly,
    which can allow cross-site scripting attacks.
    (CVE-2007-1358)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.36");
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 4.1.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

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

tomcat_check_version(fixed:"4.1.36", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4(\.1)?$");
