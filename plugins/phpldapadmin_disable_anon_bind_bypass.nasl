#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19546);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_cve_id("CVE-2005-2654");
  script_bugtraq_id(14694);
  script_osvdb_id(19067);

  script_name(english:"phpLDAPadmin Anonymous Bind Security Bypass Vulnerability");
  script_summary(english:"Checks for anonymous bind security bypass vulnerability in phpLDAPadmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpLDAPadmin, a PHP-based LDAP browser. 

The version of phpLDAPadmin installed on the remote host may allow
access to an LDAP server anonymously, even if anonymous binds have
been disabled in the application's configuration.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=322423");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e9c6bc8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpLDAPadmin 0.9.7-rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  r = http_send_recv3(method:"GET",item:string(dir, "/tree.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Get the software version if possible.
  pat = 'class="subtitle".*>phpLDAPadmin - (.+)$';
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  # Iterate over each configured ldap server and try to exploit the flaw.
  server_list = res;
  while (server_list = strstr(server_list, '<tr class="server">')) {
    server_list = strstr(server_list, '<a href="login_form.php?server_id=');

    server = server_list - '<a href="login_form.php?server_id=';
    server = server - strstr(server, '"');

    # Look for an "anonymous bind" checkbox in the login form.
    r = http_send_recv3(method:"GET", item:string(dir, "/login_form.php?server_id=", server), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # If ...
    if (
      # it looks like like phpLDAPadmin and ...
      '<form action="login.php" method="post" name="login_form">' >< res &&
      '<input type="text" name="login_dn"' >< res &&
      # it doesn't have the "anonymous bind" checkbox.
      'type="checkbox" name="anonymous_bind"' >!< res
    ) {
      # Try to exploit the flaw.
      postdata = string(
        "server_id=", server, "&",
        "anonymous_bind=on"
      );
      r = http_send_recv3(method: "POST", item: dir+"/login.php", port: port,
      	content_type: "application/x-www-form-urlencoded",
	data: postdata );
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if we could do an anonymous bind.
      if (
        "Successfully logged into server" >< res &&
        "(Anonymous Bind)" >< res
      ) {
        security_warning(port);
        exit(0);
      }
    }
  }

  # Check the version since the exploit won't works if the
  # LDAP servers don't actually allow anonymous binds.
  if (ver && ver =~ "^0\.9\.([0-5]|6($|[ab]|c($|-[0-4])))") {
    report = string(
      "Note that Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of phpLDAPadmin installed\n",
      "there.\n"
    );
    security_warning(port:port, extra: report);
    exit(0);
  }
}
