#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57802);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/23 16:10:43 $");

  script_cve_id("CVE-2011-4057");
  script_bugtraq_id(51382);
  script_osvdb_id(78223);
  script_xref(name:"CERT", value:"659515");

  script_name(english:"CodeMeter TCP Packet Parsing Unspecified Remote DoS");
  script_summary(english:"Checks the CodeMeter WebAdmin version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 4.40 (4.40.687.500). It is 
affected by a flaw in parsing specially crafted packets sent to TCP
port 22350, which a remote attacker can exploit to cause a denial of
service.");
  # https://web.archive.org/web/20121130111920/http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1098ea2");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN78901873/index.html");
  # http://www.wibu.com/en/downloads-user-software/downloads/downloadFile/changelog-en-1253/298/download.html
  # script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b5c150a");
  script_set_attribute(attribute:"see_also", value:"http://www.wibu.com/downloads-user-software.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to CodeMeter 4.40 (4.40.687.500) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("codemeter_webadmin_detect.nasl");
  script_require_keys("installed_sw/CodeMeter");
  script_require_ports("Services/www", 22350);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "CodeMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:22350, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port    : port,
  exit_if_unknown_ver:TRUE
);

dir = install['path'];
install_url = build_url(port:port,qs:dir);

version = install['version'];
disp_ver = install['display_version'];

fixed_version = "4.40";
fixed_version_ui = "4.40 (4.40.687.500)";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + disp_ver +
      '\n  Fixed version     : ' + fixed_version_ui +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, disp_ver);
