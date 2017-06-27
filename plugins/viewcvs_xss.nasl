#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14823);
 script_version("$Revision: 1.20 $"); 

 script_cve_id("CVE-2002-0771");
 script_bugtraq_id(4818);
 script_osvdb_id(6458);

 script_name(english:"ViewCVS viewcvs.cgi Multiple Parameter XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running ViewCVS, a tool written in Python to
browse CVS repositories via the web.

The version of ViewCVS running on the remote host has a cross-site
scripting vulnerability.  Input to the 'viewcvs' parameter is not
properly sanitized.  A remote attacker could exploit this by tricking
a user into requesting a maliciously crafted URL, resulting in the
execution of arbitrary script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2002/May/170"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/18");
 script_cvs_date("$Date: 2016/11/15 19:41:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:viewcvs:viewcvs");
  script_end_attributes();

 summary["english"] = "Checks for the version of ViewCVS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(url)
{
  local_var r, req;
  req = http_get(item:string(url, "/viewcvs.cgi/?cvsroot=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);

  if ('The CVS root "<script>foo</script>" is unknown' >< r)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}


foreach dir (cgi_dirs())
{
 check(url:dir);
}
