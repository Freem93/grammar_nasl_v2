#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56070);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2011-3190");
  script_bugtraq_id(49353);
  script_osvdb_id(74818);

  script_name(english:"Apache Tomcat 7.x < 7.0.21 Arbitrary AJP Message Control");
  script_summary(english:"Checks the Apache Tomcat version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability that allows an attacker to have control over AJP
messages.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.21. It is,
therefore, affected by a vulnerability that allows an attacker to have 
control over AJP messages.

Specially crafted requests are incorrectly processed by Tomcat and can
cause the server to allow injection of arbitrary AJP messages. This
can lead to an authentication bypass and the disclosure of sensitive
information.

Note that this vulnerability only occurs when the following are true :

  - the org.apache.jk.server.JkCoyoteHandler AJP connector
    is not used.

  - POST requests are accepted.

  - the request body is not processed.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=51698");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.21");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 7.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/02");

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

tomcat_check_version(fixed:"7.0.21", min:"7.0.0", severity:SECURITY_HOLE, granularity_regex:"^7(\.0)?$");
