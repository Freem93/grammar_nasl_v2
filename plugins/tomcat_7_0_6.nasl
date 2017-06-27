#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51976);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2011-0013");
  script_bugtraq_id(46174);
  script_osvdb_id(71557);
  script_xref(name:"Secunia", value:"43198");

  script_name(english:"Apache Tomcat 7.x < 7.0.6 Manager Interface XSS");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.6. It is,
therefore, affected by a cross-site scripting vulnerability in its
HTML Manager interface. A remote attacker can exploit this to inject
code into a user's browser via a crafted URL.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b4b157f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Feb/78");
  script_set_attribute(attribute:"solution", value:"Update Apache Tomcat to version 7.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");

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

tomcat_check_version(fixed:"7.0.6", min:"7.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^7(\.0)?$");
