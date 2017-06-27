#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57080);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2011-3190",
    "CVE-2011-3375",
#   "CVE-2011-4084",  < Mitre marked this as duplicate
    "CVE-2011-4858",
    "CVE-2012-0022"
  );
  script_bugtraq_id(49353, 51200, 51442, 51447);
  script_osvdb_id(74818, 78113, 78331, 78573);
  script_xref(name:"CERT", value:"903934");

  script_name(english:"Apache Tomcat 6.x < 6.0.35 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.x listening on the remote host is prior to 6.0.35. It is,
therefore, affected by multiple vulnerabilities :

  - Specially crafted requests are incorrectly processed
    by Tomcat and can cause the server to allow injection
    of arbitrary AJP messages. This can lead to
    authentication bypass and disclosure of sensitive
    information. (CVE-2011-3190)

  - An information disclosure vulnerability exists. Request
    information is cached in two objects and these objects
    are not recycled at the same time. Further requests can
    obtain sensitive information if certain error conditions
    occur. (CVE-2011-3375)

  - Large numbers of crafted form parameters can cause
    excessive CPU consumption due to hash collisions.
    (CVE-2011-4858, CVE-2012-0022)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=51698#c2");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1162959");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.35");
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 6.0.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/12");

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

tomcat_check_version(fixed:"6.0.35", min:"6.0.0", severity:SECURITY_HOLE, granularity_regex:"^6(\.0)?$");
