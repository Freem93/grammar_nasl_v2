#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69051);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-2184");
  script_bugtraq_id(60570);
  script_osvdb_id(94282);

  script_name(english:"Movable Type 5.2.X < 5.2.6 Unspecified Vulnerability");
  script_summary(english:"Checks the version of Movable Type");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a blog application that is affected by
an unspecified vulnerability."
);
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Movable Type install hosted on the
remote web server is affected by an unspecified flaw when the
'comment_state()' function is processed by the 'unserialize()' function. 
This flaw is due to an issue with the Perl 'Storable::thaw()' function,
which is considered unsafe to use on untrusted input. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2013/06/14/1");
  # http://perl5.git.perl.org/perl.git/commit/664f237a84176c09b20b62dbfe64dd736a7ce05e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16908ac9");
  # http://www.movabletype.org/documentation/appendices/release-notes/movable-type-526-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20e825b8");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("movabletype_detect.nasl");
  script_require_keys("www/movabletype", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname : "movabletype",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_loc = build_url(port:port, qs:dir);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Movable Type", install_loc);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 5.2.x less than 5.2.6 are vulnerable
if (
  version =~ "^5\.2" &&
  (ver[0] == 5 && ver[1] == 2 && ver[2] < 6)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 5.2.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_loc, version);
