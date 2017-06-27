#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55629);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_cve_id("CVE-2011-0549");
  script_bugtraq_id(48318);
  script_osvdb_id(73658);

  script_name(english:"Symantec Web Gateway forget.php Blind SQL Injection (SYM11-008)");
  script_summary(english:"Checks SWG version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application running on the remote host has a SQL
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of
Symantec Web Gateway running on the remote host has a SQL injection
vulnerability.  Input to the 'username' parameter of the 'forget.php'
script is not properly sanitized.

A remote, unauthenticated attacker could exploit this to manipulate
database queries."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-233/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d16cb7bf");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);
dir = install['dir'];
ver = install['ver'];
fix = '5.0.1';

if (ver == UNKNOWN_VER)
  exit(1, 'Unable to get the version number of Symantec Web Gateway on port ' + port + '.');

# Symantec says only versions 4.5.x are vulnerable, even though the recommendation is
# to upgrade to 5.0.1
ver_fields = split(ver, sep:'.', keep:FALSE);

if (int(ver_fields[0]) == 4 && int(ver_fields[1]) == 5)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(qs:dir, port:port) +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The Symantec Web Gateway ' + ver + ' installed on port ' + port + ' is not affected.');
