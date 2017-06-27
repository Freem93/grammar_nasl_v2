#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45059);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2010-0714");
  script_bugtraq_id(38412);
  script_osvdb_id(62846);
  script_xref(name:"Secunia", value:"38174");

  script_name(english:"IBM Multiple Products login.php Query String XSS");
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
"The version of IBM WebSphere Portal / IBM Lotus Web Content
Management running on the remote host has a cross-site scripting
vulnerability.  The query string passed to login.php is not properly
sanitized. 

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in the execution of
arbitrary script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hacktics.com/content/advisories/AdvIBM20100224.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Feb/225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg21421469"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant fix referenced in the IBM advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/24");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/15");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 10040);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:10040);
xss = '"><script>alert("'+SCRIPT_NAME+'-'+unixtime()+'")</script>';
dir = '/wps/wcm/webinterface/login';
page = '/login.jsp';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:page,
  qs:xss,
  pass_str:'value="'+xss,
  ctrl_re:'<title>IBM Lotus Web Content Management.</title>'
);

if (!exploited)
  exit(0, build_url(qs:dir+page, port:port) + " is not affected.");


