#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20952);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-3630");
  script_bugtraq_id(16729);
  script_osvdb_id(23350);

  script_name(english:"Fedora Directory Server Crafted IFRAME adm.conf Admin Server Password Disclosure");
  script_summary(english:"Checks for an information disclosure vulnerability in Fedora Directory Server Administration Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Fedora Directory Server, a
directory server implementation for Fedora Core. 

The Administration Server, which is used to manage Fedora DS, allows
an unauthenticated attacker to retrieve the admin password hash
through a simple GET request." );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=174837" );
 script_set_attribute(attribute:"see_also", value:"http://directory.fedora.redhat.com/wiki/FDS10Announcement" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Fedora Directory Server 1.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/02");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: the default port is generally chosen randomly at setup.
port = get_http_port(default:80);


# If the banner looks like Fedora DS administration server...
banner = get_http_banner(port:port);
if (banner && "Server: Apache/2.0" >< banner) {
  # Try to exploit the flaw to read the admin password.
  w = http_send_recv3(method:"GET",item:"/admin-serv/config/admpw", port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # There's a problem if it looks like a password.
  if (
    "Admin-Server: Fedora-Administrator" >< res &&
    # eg, "admin:{SHA}xZL4fZJ4r8q+M3l6dmoQl7tiykg="
    egrep(pattern:"^[^:]+:\{SHA\}.{28}$", string:res)
  ) {
    security_warning(port);
    exit(0);
  }
}
