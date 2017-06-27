#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55859);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2011-2729");
  script_bugtraq_id(49143);
  script_osvdb_id(74541);

  script_name(english:"Apache Tomcat 7.x < 7.0.20 'jsvc' Information Disclosure");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.20. It is,
therefore, affected by an information disclosure vulnerability due to
a component that Apache Tomcat relies on called 'jsvc' which does not
drop capabilities after starting and can allow access to sensitive
files owned by the super user.

Note that this vulnerability only affects Linux operating systems and
only when the following are true :

  - jsvc is compiled with libpcap

  - the '-user' parameter is used

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.20");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 7.0.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");

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

tomcat_check_version(fixed:"7.0.20", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
