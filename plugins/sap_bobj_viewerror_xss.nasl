#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44343);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_bugtraq_id(37900, 37972);
  script_xref(name:"Secunia", value:"38217");

  script_name(english:"SAP BusinessObjects viewError.jsp 'error' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of SAP BusinessObjects installed on the remote web server
has a cross-site scripting vulnerability.  Input passed to the
'error' parameter of '/PerformanceManagement/jsp/viewError.jsp' is
not properly sanitized.

A remote attacker could exploit this by tricking a user into
requesting a specially crafted URL, resulting in the execution of
arbitrary script code.

This version of BusinessObjects reportedly has several other
vulnerabilities, though Nessus has not checked for those issues."
  );
   # http://web.archive.org/web/20100403074821/http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9cfae68");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Jan/572"
  );
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  # ? not sure if a patch has been published ?

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("sap_bobj_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6405, 8080);
  script_require_keys("www/sap_bobj");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:6405);
install = get_install_from_kb(appname:'sap_bobj', port:port);
if (isnull(install))
  exit(1, "SAP BusinessObjects wasn't found on port " + port + ".");

# test_cgi_xss() will return if it receives an empty string for the dir
dir = install['dir']+'/';
page = 'PerformanceManagement/jsp/viewError.jsp';
xss = "<script>alert('"+SCRIPT_NAME+'-'+unixtime()+"')</script>";
qs = 'error='+xss;
ctrl_re = str_replace(string:xss, find:'(', replace:'\\(');
ctrl_re = str_replace(string:ctrl_re, find:')', replace:'\\)');
ctrl_re = '^'+ctrl_re+'[ \r\n\t]+$';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir+'/'),
  cgi:page,
  qs:qs,
  pass_str:xss,
  ctrl_re:ctrl_re
);

if (!exploited)
  exit(0, "The SAP BusinessObjects install at " + build_url(qs:dir+page, port:port) + " is not affected.");

