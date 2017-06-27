#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82704);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"VMware vCenter Operations Manager Web UI Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server uses a known set of default
credentials.");
  script_set_attribute(attribute:"description", value:
"The web UI component of VMware vCenter Operations Manager uses a known
set of default credentials. An attacker can use these to gain access
to the system.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/vrealize-operations/");
  script_set_attribute(attribute:"solution", value:"Change the admin user password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_operations");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_operations_manager_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/VMware vCenter Operations Manager");
  script_require_ports("Services/www", 443,80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if(supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "VMware vCenter Operations Manager";

get_install_count(app_name:app, exit_if_zero:TRUE);

port    = get_http_port(default:443);
install = get_single_install(
  app_name : app,
  port     : port
);
url = build_url(port:port, qs:install["path"]+"admin/");

proto = "http";
if(get_port_transport(port) > ENCAPS_IP)
  proto = "https";

# Make GWT Request for version Information
headers = make_array(
  "Content-Type",      "text/x-gwt-rpc; charset=UTF-8",
  "X-GWT-Permutation", rand_str(charset:"ABCDEF0123456789", length:32)
);
reqdata = "7|0|6|"+
          proto+"://"+get_host_name()+"/admin/com.vmware.cm.ui.Admin/|"+
          "2A75D70BCD17CE0AAFCC3ACC64087B14|"+
          "com.vmware.cm.ui.client.AuthenticationService|"+
          "authenticateAdminUser|java.lang.String/2004016611|vmware|1|2|3|4|1|5|6|";

# Can take up to 10s to get response from bad password
http_set_read_timeout(10);
res = http_send_recv3(
  method       : "POST",
  item         : "/admin/com.vmware.cm.ui.Admin/authenticationService",
  port         : port,
  add_headers  : headers,
  data         : reqdata,
  exit_on_fail : TRUE
);

# Verify response
if(
   "200 OK"               >!< res[0] ||
   "application/json"     >!< res[1] ||
   "Path=/admin; Secure;" >!< res[1] ||
   res[2] !~ "\/\/OK\[1,\[\],0,7\]"
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

if (report_verbosity > 0)
{
  report  = '\n  Username : admin'  +
            '\n  Password : vmware' +
            '\n';
  header  = 'Nessus was able to gain access using the following URL';
  trailer = 'and the following set of credentials :\n' + report;
  report  = get_vuln_report(
    items   : "/admin/",
    port    : port,
    header  : header,
    trailer : trailer
  );
  security_hole(port:port, extra:report);
}
else security_hole(port);
