#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42212);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"Infoblox IPAM Appliance Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Infoblox IPAM appliance. Nessus
was able to log into the remote web console using default credentials.");
  # http://web.archive.org/web/20090724043122/http://www.infoblox.com/solutions/ip-address-management.cfm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d0ee176" );
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation and follow the steps to change the
default password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
 
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 2000);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

login = "admin";
password = "infoblox";

port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = "/ipam/";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

if ("Infoblox IP Address Manager" >< res[2])
{
  
  res = http_send_recv3(
    method:"POST", 
    item:"/ipam/?wicket:bookmarkablePage=:com.infoblox.nios.ui.page.login.VirtualNiosLoginPage&wicket:interface=:0:loginForm::IFormSubmitListener::", 
    port:port,
    exit_on_fail: TRUE,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data:"id1_hf_0=&username="+login+"&password="+password+"&loginButton=Login"
  );

  # If the login was successful we should see 'Location' and 'Set-Cookie'
  # header set with JSESSIONID
 
  h = parse_http_headers(status_line: res[0], headers: res[1]);
  location = h["location"];
  
  if (
    "Set-Cookie: JSESSIONID=" >< res[1] &&
     ereg(pattern:"jsessionid=[a-zA-Z0-9]+\?wicket:bookmarkablePage=:com\.infoblox\.nios\.ui\.page\.dashboard\.LoadingDashboardPage",string:location)
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        'URL      : ' + build_url(port:port, qs:url) + '\n' +
        'User     : ' + login + '\n' +
        'Password : ' + password + '\n';
      security_hole(port:port,extra:report);
    }
    else security_hole(port);  
  }
}
