#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52659);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2011-1038");
  script_bugtraq_id(46471);
  script_osvdb_id(71108);
  script_xref(name:"Secunia", value:"43430");

  script_name(english:"IBM Lotus Sametime Server stconf.nsf messageString Parameter XSS");
  script_summary(english:"Tries to inject an XSS payload through messageString parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that contains a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:

"The version of Lotus Sametime on the remote host contains a
cross-site scripting vulnerability because it fails to sanitize input
to the 'messageString' parameter of the 'stconf.nsf' script before
including it in a web page.

An attacker can leverage this issue by enticing a user to follow a
malicious URL, causing attacker-specified script code to run inside
the user's browser with the context of the affected site.  Information
harvested this way may aid in launching further attacks.

Versions of Lotus Sametime containing this vulnerability may also
contain another cross-site scripting vulnerability in stcenter.nsf,
but this script did not test for that."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/516563");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/516582"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/lotus_sametime");
  script_require_ports("Services/www", 80, 8088);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Check that Lotus Sametime is installed on this port.
port = get_http_port(default:80);

install = get_kb_item("www/lotus_sametime/" + port + "/installed");

if(isnull(install))
  exit(0, 'Lotus Sametime install not found on port ' + port);

dir = "";

# Create a query to trigger the vulnerability.
xss = "<script>alert('" + SCRIPT_NAME  + "');</script>";
test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : "/stconf.nsf/WebMessage",
  qs       : "OpenView&messageString=" + xss,
  pass_str : xss,
  ctrl_re  : "IBM Lotus Sametime"
);
