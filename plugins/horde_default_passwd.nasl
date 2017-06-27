#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20171);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/09/24 16:49:06 $");

  script_cve_id("CVE-2005-3344");
  script_bugtraq_id(15337);
  script_osvdb_id(24117);
  script_xref(name:"DSA", value:"884");

  script_name(english:"Horde Admin Account Default Password");
  script_summary(english:"Checks for default admin password in Horde");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that uses a default
administrative password.");
  script_set_attribute(attribute:"description", value:
"The remote installation of horde uses an administrative account with
no password.  An attacker can leverage this issue to gain full control
over the affected application and to run arbitrary shell, PHP, and SQL
commands using the supplied admin utilities. 

Note that while the advisory is from Debian, the flaw is not specific
to that distribution - any installation of Horde that has not been 
completely configured is vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www.horde.org/horde/docs/?f=INSTALL.html#configuring-horde");
  script_set_attribute(attribute:"solution", value:
"Either remove Horde or complete its configuration by configuring
an authentication backend.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/horde");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);
app = "Horde";

# Test an install.
install = get_kb_item_or_exit("www/" + port + "/horde");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  install_url = build_url(qs:dir, port:port);

  # Try to access the login script.
  r = http_send_recv3(method:"GET", item:dir + "/login.php", port:port, exit_on_fail:TRUE);
  res = r[2];

  # There's a problem if we get in. [If it were configured, we'd
  # get redirected back to login.php.]
  if ('<frame name="horde_' >< res) 
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to gain access to the administrative interface without' +
        '\ncredentials :' +
        '\n' +
        '\n  URL      : ' + install_urli + "/login.php" +
        '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, app, port);
