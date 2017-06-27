#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83741);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_bugtraq_id(73236);
  script_osvdb_id(119803);

  script_name(english:"Websense TRITON 7.8 Source Code Disclosure");
  script_summary(english:"Attempts to exploit the flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server is affected by a source code
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Websense TRITON running on the remote web server
contains a flaw in handling a JSP script request having an appended
double quote character. This causes the source code of the script to
be returned instead of it being executed. An unauthenticated, remote 
attacker can exploit this flaw to view the source code of the
application, allowing further attacks to be carried out.");
  # https://www.securify.nl/advisory/SFY20140907/source_code_disclosure_of_websense_triton_jsp_files_via_double_quote_character.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81de34db");
  # http://www.websense.com/support/article/kbarticle/Vulnerabilities-resolved-in-TRITON-APX-Version-8-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46d757d");
  script_set_attribute(attribute:"solution", value:"Update to version 7.8.4 Hotfix 02 or 8.0.0.");
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

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
item     = "/triton/login/pages/certificateDone.jsp%22";
if(install["path"] != "/")
  item = install["path"] + item;

res = http_send_recv3(
  method : "GET",
  item   : item,
  port   : port,
  exit_on_fail:TRUE
);

if ('<%@page import="com.websense' >< res[2] && 'bblogin.after' >< res[2])
{
  if (report_verbosity > 0)
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
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
