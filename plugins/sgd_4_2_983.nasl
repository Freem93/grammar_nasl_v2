#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22495);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2006-4958", "CVE-2006-4959");
  script_bugtraq_id(20135, 20276);
  script_osvdb_id(
    29219, 
    29220, 
    29221, 
    29222, 
    29223, 
    29224, 
    29225, 
    29226
  );

  script_name(english:"Sun Secure Global Desktop / Tarantella < 4.20.983 Multiple XSS");
  script_summary(english:"Checks version of Sun Secure Global Desktop / Tarantella");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are vulnerable to
cross-site scripting attacks." );
  script_set_attribute(attribute:"description", value:
"Sun Secure Global Desktop or Tarantella, a Java-based program for
web-enabling applications running on a variety of platforms, is
installed on the remote web server. 

According to the version reported in one of its scripts, the
installation of the software on the remote host fails to sanitize
user-supplied input to several unspecified parameters before using it
to generate dynamic web content.  An unauthenticated, remote attacker
may be able to leverage these issues to inject arbitrary HTML and
script code into a user's browser to be evaluated within the security
context of the affected website." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/446566/30/0/threaded" );
   # http://web.archive.org/web/20061011064105/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102650-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d074268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Secure Global Desktop version 4.20.983 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/03");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/21");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Do a banner check.
w = http_send_recv3(method:"GET",
  item:"/tarantella/cgi-bin/secure/ttawlogin.cgi/?action=bootstrap", 
  port:port
);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

# If there's a version...
if ('<PARAM NAME="TTAVersion"' >< res)
{
  # Extract it.
  pat = '^ *<PARAM NAME="TTAVersion" VALUE="([^"]+)">.*';
  line = egrep(pattern:pat, string:res);
  if (line)
  {
    ver = ereg_replace(pattern:pat, string:line, replace:"\1");
    if (ver)
    {
      # There's a problem if it's a version before 4.20.983.
      ver = split(ver, sep:'.', keep:FALSE);
      if (
        int(ver[0]) < 4 ||
        (
          int(ver[0]) == 4 &&
          (
            int(ver[1]) < 20 ||
            (int(ver[1]) == 20 && int(ver[2]) < 983)
          )
        )
      ) {
	  security_warning(port);
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
    }
  }
}
