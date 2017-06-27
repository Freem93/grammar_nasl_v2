#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74245);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2014-0075",
    "CVE-2014-0096",
    "CVE-2014-0099",
    "CVE-2014-0119"
  );
  script_bugtraq_id(67667, 67668, 67669, 67671);
  script_osvdb_id(107450, 107452, 107453, 107475);

  script_name(english:"Apache Tomcat 6.0.x < 6.0.40 Multiple Vulnerabilities");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0.x listening on the remote host is prior to 6.0.40. It is,
therefore, affected by the following vulnerabilities :

  - An error exists related to chunk size and chunked
    requests that allows denial of service attacks.
    (CVE-2014-0075)

  - An error exists related to XSLT handling and security
    managers that allows a security bypass related to 
    external XML entities. (CVE-2014-0096)

  - An error exists related to content length header
    handling and using the application behind a reverse
    proxy that allows a security bypass. (CVE-2014-0099)

  - An error exists that allows undesired XML parsers to be
    injected into the application by a malicious web
    application, allows the bypassing of security controls,
    and allows the processing of external XML entities.
    (CVE-2014-0119)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.41 or later.

Note that while version 6.0.40 fixes these issues, that version was
not officially released, and the vendor recommends upgrading to 6.0.41
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

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

# Note that 6.0.40 contained the fix,
# but was never released
tomcat_check_version(fixed:"6.0.40", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");
