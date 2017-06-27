#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47696);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2006-7195");
  script_bugtraq_id(28481);
  script_osvdb_id(34887);

  script_name(english:"Apache Tomcat Implicit Objects XSS");
  script_summary(english:"Checks for XSS in Apache Tomcat Implicit Objects Page.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Apache Tomcat server is affected by a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Apache Tomcat server is affected by a cross-site scripting
vulnerability in the 'jsp-examples/jsp2/el/implicit-objects.jsp'
example webapp due to a failure to properly filter user-supplied
header values."
  );
   # http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.18,_5.0.SVN
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a131c24"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to version 5.0.SVN / 5.5.18 or later. Alternatively, undeploy
Apache Tomcat example web applications."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("url_func.inc");
include("http.inc");

port = get_http_port(default: 8080);

if (
  !test_cgi_xss(
    port        : port,
    cgi         : 'implicit-objects.jsp',
    ctrl_re     : '<td>\\$\\{header\\["accept"\\]\\}</td>',
    pass_str    : '<td><script>alert("'+SCRIPT_NAME+'")</script></td>',
    dirs        : make_list('/jsp-examples/jsp2/el/'),
    add_headers : make_array('Accept', '<script>alert("'+SCRIPT_NAME+'")</script>') 
  )
) exit(0, "The Tomcat install listening on port " + port + " is not affected.");
