#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47028);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 20:30:59 $");

  script_cve_id("CVE-2008-3271");
  script_bugtraq_id(31698);
  script_xref(name:"Secunia", value:"32213");
  script_osvdb_id(49062);

  script_name(english:"Apache Tomcat 5.x < 5.5.1 Information Disclosure");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 5.x listening on the remote host is prior to 5.5.1. It is,
therefore, affected by an information disclosure vulnerability.

Specifically, it may allow requests from a non-permitted IP address to
gain access to a context that is protected with a valve that extends
RequestFilterValve.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=25835");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Oct/81");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 5.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/16");

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

tomcat_check_version(fixed:"5.5.1", min:"5.0.0", severity:SECURITY_WARNING, granularity_regex:"^5(\.5)?$");
