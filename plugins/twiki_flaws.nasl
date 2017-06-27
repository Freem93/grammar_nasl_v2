#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(17210);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/15 19:41:08 $");

  script_cve_id("CVE-2005-0516");
  script_bugtraq_id(12637, 12638);
  script_osvdb_id(14126);

  script_name(english:"TWiki ImageGalleryPlugin Shell Command Injection");
  script_summary(english:"Checks version of TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of TWiki running on the
remote host is affected by a shell command injection vulnerability in
the ImageGalleryPlugin component. 

In addition, the wording of a 'robustness' patch released by the
vendor indicates this version may be affected by other input
validation issues. It should be noted that the patch may contain
proactive security enhancements but they may not fix specific
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Feb/562");
  script_set_attribute(attribute:"solution", value:"Apply the TWiki robustness patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_require_keys("installed_sw/TWiki", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (egrep(pattern:"(1999|200[0-4])", string:ver))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : apply the referenced patch' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
