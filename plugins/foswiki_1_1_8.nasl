#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65059);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2013-1666");
  script_bugtraq_id(58026);
  script_osvdb_id(90345);

  script_name(english:"Foswiki < 1.1.8 MAKETEXT Macro Arbitrary Code Injection");
  script_summary(english:"Checks version of Foswiki.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI application that is affected by a
code injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the instance of Foswiki installed on
the remote host is affected by a code injection vulnerability in the
'%MAKETEXT{}%' macro.  An incomplete fix to CVE-2012-6329 left this
attack vector available in which an attacker can invoke arbitrary Perl
modules by escaping brackets within 'MAKETEXT =~~[Some::Module,~~]='. 

Note that Foswiki installations in which localization is not enabled or
'Locale::Maketext' has been upgraded to version 1.23, are not affected. 

Note also that Nessus has not tested for this issue, but instead, has
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://foswiki.org/Support/SecurityAlert-CVE-2013-1666");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to version 1.1.8 or later or apply the hotfix in the
referenced URL.  Additionally, Locale::Maketext should be upgraded to
version 1.23."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foswiki:foswiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("foswiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport", "www/foswiki");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "foswiki",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir+"/view");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Foswiki", install_url);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.0.0 - 1.1.7 are affected
if (
  (ver[0] == 1 && ver[1] < 1) ||
  (ver[0] == 1 && ver[1] == 1 && ver[2] < 8)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.1.8' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Foswiki", install_url, version);
