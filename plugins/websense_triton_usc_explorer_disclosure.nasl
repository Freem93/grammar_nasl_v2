#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83740);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/22 14:14:42 $");

  script_cve_id("CVE-2015-2748");
  script_bugtraq_id(73236, 73241);
  script_osvdb_id(119805);

  script_name(english:"Websense TRITON Unauthorized File Disclosure");
  script_summary(english:"Attempts to exploit the flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server is affected by an
unauthorized file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Websense TRITON running on the remote web server does
not properly restrict access to files in the 'explorer_wse/' path. A
remote attacker, by using a direct request to a Web Security incident
report or the Explorer configuration (websense.ini) file, can thereby
gain access to sensitive information.");
  # https://www.securify.nl/advisory/SFY20140909/missing_access_control_on_websense_explorer_web_folder.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a11e40c");
  # http://www.websense.com/support/article/kbarticle/Vulnerabilities-resolved-in-TRITON-APX-Version-8-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46d757d");
  script_set_attribute(attribute:"solution", value:"Update to version 8.0.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_unified_security_center");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("websense_triton_usc_detect.nbin");
  script_require_keys("installed_sw/Websense TRITON");
  script_require_ports("Services/www", 9443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Websense TRITON";
get_install_count(app_name:app, exit_if_zero:TRUE);
port     = get_http_port(default:9443);
install  = get_single_install(app_name:app,port:port);
url      = build_url(port:port, qs:install["path"]);
item     = "/explorer_wse/websense.ini";
if(install["path"] != "/")
  item = install["path"] + item;

res = http_send_recv3(
  method : "GET",
  item   : item,
  port   : port,
  exit_on_fail:TRUE
);

if ('[PolicyServer]' >< res[2] && '# Websense' >< res[2])
{
  security_report_v4(
    port     : port,
    request  : make_list(build_url(port:port,qs:item)),
    output   : res[2],
    severity : SECURITY_WARNING,
    generic  : TRUE
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
