#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87600);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");


  script_cve_id("CVE-2015-5371");
  script_bugtraq_id(51639);
  script_osvdb_id(123972);
  script_xref(name:"ZDI", value:"ZDI-15-275");

  script_name(english:"SolarWinds Storage Manager AuthenticationFilter Script Upload RCE");
  script_summary(english:"Attempts to bypass authentication and upload file directly.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Storage Manager running on the remote host
is affected by a remote code execution vulnerability due to a flaw in
the AuthenticationFilter class. An unauthenticated, remote attacker
can exploit this to bypass the authentication filter and upload
arbitrary scripts, resulting in the execution of arbitrary code under
the context of SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-275/");
  # http://downloads.solarwinds.com/solarwinds/Release/HotFix/STM-v6.1.0-HotFix1.zip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dec932e");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"SolarWinds Storage Manager 5.1.2 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_storagemanager_detect.nasl");
  script_require_keys("www/solarwinds_storage_manager");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

app_name = "SolarWinds Storage Manager";
app_name_kb = "solarwinds_storage_manager";
get_install_count(app_name:app_name_kb, exit_if_zero:TRUE);
port = get_http_port(default:9000); 
install = get_single_install(app_name:app_name_kb, port:port);
path = install['path'];
url = build_url(qs:path, port:port);
postdata = '';
res = http_send_recv3(port:port, method: 'POST',
        item: "/images/../jsp/ProcessFileUpload.jsp",
        data: postdata,
        content_type: "multipart/form-data; boundary=----GVSfnwGTvjBMvr",
        exit_on_fail: TRUE );
# see if upload is successful
if (
  "Upload Successful!" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to bypass authentication and directly access\n' +
      'file upload functionality with the following HTTP Request : \n\n' + 
      http_last_sent_request() + '\n';
    security_hole(port:port, extra: report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);
