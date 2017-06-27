#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58749);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_name(english:"Citrix XenServer Workload Balancer Detection");
  script_summary(english:"Looks for XML API errors.");

  script_set_attribute(attribute:"synopsis", value:"A virtual machine management daemon is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Citrix XenServer Workload Balancer, a daemon for migrating virtual
machines between Xen hosts based on load, is running on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/xenserver/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:xenserver_workload_balancer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8012);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

function mkfault()
{
  return
    "<s:Fault>" +
    "<faultcode[^>]*>" +
    _FCT_ANON_ARGS[0] +
    "</faultcode>" +
    "<faultstring[^>]*>" +
    _FCT_ANON_ARGS[1] +
    "</faultstring>" +
    "</s:Fault>";
}

# Get the ports that webservers have been found on, defaulting to the
# used in default installs. Since this port has some odd behaviours,
# ensure that the library doesn't write it off as broken.
port = get_http_port(default:8012, dont_break:TRUE);

# Try to find some hint that this might be a WLB server.
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : "/Citrix.Dwm.WorkloadBalance/Service",
  exit_on_fail : TRUE
);

# Check if this looks like the error WLB gives to GET requests.
fault = mkfault(
  "a:ActionNotSupported",
  "Action '' did not match any operations in the target contract"
);
if (res[2] !~ fault)
  exit(0, "Citrix XenServer Workload Balancer wasn't detected on port " + port + ".");

# Put together a list of directories we should check for WLB in.
dirs = cgi_dirs();

# Put together checks for different pages that we can scrape version
# information from.
checks = make_array();

# This covers v6.0.x.
regexes = make_list();
regexes[0] = make_list(
  mkfault(
    "Receiver",
    "Object reference not set to an instance of an object"
  )
);
regexes[1] = make_list();
checks["/Citrix.Dwm.WorkloadBalance/Service"] = regexes;

# Choose one of the few methods that does not require any parameters.
method = "GetDiagnostics";

# Create the SOAP method call.
soap =
  '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
     <s:Body>
       <" + method + " xmlns="http://schemas.citrix.com/DWM">
         <request xmlns:i="http://www.w3.org/2001/XMLSchema-instance"></request>
       </" + method + ">
     </s:Body>
   </s:Envelope>';

# The function that we're trying to call is indicated by a header.
hdrs = make_array(
  'SOAPAction', '"http://schemas.citrix.com/DWM/IWorkloadBalance/' + method + '"',
  'Content-Type', 'text/xml; charset=utf-8'
);

# Find where WLB's web interface is installed.
installs = find_install(
  appname     : "xenserver_workload_balancer",
  method      : "POST",
  data        : soap,
  add_headers : hdrs,
  checks      : checks,
  dirs        : dirs,
  port        : port
);

if (isnull(installs))
  exit(0, "Citrix XenServer Workload Balancer wasn't detected on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Citrix XenServer Workload Balancer",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
