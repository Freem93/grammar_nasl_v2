#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CVE
#

include("compat.inc");

if(description)
{
 script_id(10518);
 script_version ("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_cve_id("CVE-2000-1016");
 script_bugtraq_id(1707);
 script_osvdb_id(417);

 script_name(english:"/doc/packages Directory Browsable (deprecated)");
 script_summary(english:"Checks if /doc/packages browsable.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The /doc/packages directory is browsable.  This directory contains the
versions of the packages installed on this host.  A remote attacker can
use this information to mount further attacks.
This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Sep/435" );
 script_set_attribute(attribute:"solution", value:
"Use access restrictions for the /doc directory.  If you use Apache
you might use this in your access.conf:

  <Directory /usr/doc>
  AllowOverride None
  order deny,allow
  deny from all
  allow from localhost
  </Directory>" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/21");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl","doc_browsable.nasl", "http_version.nasl");
 script_require_keys("www/doc_browseable");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

#
# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dir = "/doc/packages/";
r = http_send_recv3(method:"GET", item: dir, port:port);
if (isnull(r)) exit(0);

code = r[0];
buf = strcat(r[1], '\r\n', r[2]);
buf = tolower(buf);
must_see = "index of /doc";

  if((ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 200 "))&&(must_see >< buf))
  {
    	security_warning(port);
	set_kb_item( name: 'www/'+port+'/content/directory_index', value: dir);
  }

