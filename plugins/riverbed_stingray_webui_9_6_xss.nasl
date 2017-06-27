#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77684);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/23 21:29:46 $");

  script_cve_id("CVE-2014-5264", "CVE-2014-5348");
  script_bugtraq_id(69243);
  script_osvdb_id(110144, 138708);

  script_name(english:"Riverbed SteelApp (Stingray) Traffic Manager < 9.7 Multiple XSS");
  script_summary(english:"Checks the version of the Riverbed SteelApp (Stingray) web UI.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Riverbed SteelApp (formerly known as Stingray)
Traffic Manager running a version of the web user interface prior to
9.7. It is, therefore, affected by multiple cross-site scripting
vulnerabilities in the 'locallog.cgi' script due to improper
validation of user-supplied input to the 'logfile' parameter. A
context-dependent attacker can exploit this, via a specially crafted
request, to execute arbitrary script code in the in a user's browser 
session.");
  # https://supportkb.riverbed.com/support/index?page=answerlink&url=3bH0FLZcM9udS9KSoLg027nR9D!xID-YAxWRhSnd595RZFoY769z-34iMW9JTyJaecQTcOcWVfzpAumv5IZoksRB6d5WuBYoXGLwAQuJ-8eTZ-V4vEGUkG1nbhho6cSqZzxMmclVgo7F4Z4hrAjMVRnaEZfh1P-xlq43fPWQLVOm9BQnc0CZMy0GRNnNWYvy6Al6831sFern7Hq-MP2AWzt-UniuhiQNcuWY9WPoLuI=&answerid=16777217&searchid=1409924795096
  # This is actually a link to a pdf document
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1bf742b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Riverbed SteelApp (Stingray) version 9.7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:riverbed:steelapp_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:riverbed:stingray_traffic_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("riverbed_stingray_webui_detect.nbin");
  script_require_keys("installed_sw/Stingray Traffic Manager");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Stingray Traffic Manager";

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];
url     = build_url(qs:path,port:port);

# ie 9.6r1 -> 9.6.1
version = ereg_replace(pattern:"r", replace:".", string:version);

fix = '9.7';
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSS",value: TRUE);

  if (report_verbosity > 0) 
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + install["version"] +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname+" Web UI", url, version);

