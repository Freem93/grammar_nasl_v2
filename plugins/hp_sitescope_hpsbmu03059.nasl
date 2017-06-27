#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76427);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2014-2614");
  script_bugtraq_id(68361);
  script_osvdb_id(108709);
  script_xref(name:"HP", value:"emr_na-c04355129");
  script_xref(name:"HP", value:"HPSBMU03059");
  script_xref(name:"HP", value:"SSRT101473");

  script_name(english:"HP SiteScope Unspecified Authentication Bypass");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by an
unspecified authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP SiteScope installed on the remote host is affected
by an authentication bypass vulnerability having unspecified impact.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04355129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2954051a");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532631/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP SiteScope 11.13 with Cumulative Fixes SSRT101473 or
11.24 with Cumulative Fixes SSRT101473 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);
version = install['ver'];
dir = install['dir'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP SiteScope', build_url(port:port, qs:dir));

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

# 11.1x < 11.13 CF SSRT101473
if (
  ver[0] == 11 &&
  ver[1] >= 10 &&
  (
    ver[1] < 13 || (report_paranoia == 2 && ver[1] == 13)
  )
) fix = "11.13 with Cumulative Fixes SSRT101473";

# 11.2x < 11.24 CF SSRT101473
if (
  ver[0] == 11 &&
  ver[1] >= 20 &&
  (
    ver[1] < 24 || (report_paranoia == 2 && ver[1] == 24)
  )
) fix = "11.24 with Cumulative Fixes SSRT101473";

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'HP SiteScope',  build_url(port:port, qs:dir), version);
