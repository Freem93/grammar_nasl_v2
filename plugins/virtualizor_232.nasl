#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69045);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_bugtraq_id(61013);
  script_osvdb_id(94919);

  script_name(english:"Virtualizor < 2.3.2 PDNS Domain Deletion Security Bypass");
  script_summary(english:"Checks the version of Virtualizor");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by a
security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Virtualizor install hosted on the
remote web server is earlier than 2.3.2 and therefore affected by a
security bypass vulnerability.  Due to an unspecified flaw, an attacker
may be able to delete arbitrary PDNS domains that their user account
does not have access to. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.virtualizor.com/blog/?p=364");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:softaculous:virtualizor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("virtualizor_detect.nasl");
  script_require_keys("www/virtualizor");
  script_require_ports("Services/www", 4082, 4083);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:4082);

install = get_install_from_kb(
  appname : "virtualizor",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Virtualizor", install_url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 2.3.2 are vulnerable
if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] < 3) ||
  (ver[0] == 2 && ver[1] == 3 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.3.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Virtualizor", install_url, version);
