#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81791);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_bugtraq_id(72640);
  script_osvdb_id(118316);

  script_name(english:"NETGEAR SOAP Request Handling Remote Authentication Bypass");
  script_summary(english:"Checks for the embedded SOAP service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus has determined that the remote NETGEAR device is running an
embedded SOAP service which is used by the NETGEAR Genie application
for viewing and setting various device features. Authentication to
this service can be bypassed, and an attacker can exploit this
vulnerability to interrogate and control the device by using crafted
HTTP requests.");
  # https://github.com/darkarnium/secpub/tree/master/NetGear/SOAPWNDR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d6c6d8a");
  script_set_attribute(attribute:"solution", value:
"Allow only trusted devices access to the local network and disable
access for remote / WAN management.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:netgear:netgear-soap-service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 80, 443, 5000);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Netgear WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

# Sending a post request with a blank form
# along with the desired SOAPAction in the header
# will return the desired respond without
# requiring authentication (if vulnerable).
res = http_send_recv3(
  method       : "POST",
  item         : "/",
  port         : port,
  data         : " ",
  add_headers  : make_array("SOAPAction", "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo"),
  exit_on_fail : TRUE
);

# If successful, the response code will be '000'
# We'll also check for a couple of items that are
# expected from the above query.
if (
  "<ResponseCode>000</ResponseCode>" >< res[2] &&
  "<Description>Netgear" >< res[2] &&
  "<Firmwareversion>" >< res[2]
)
{
  output = strstr(res[2], "<div id='nav_menu'");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(http_last_sent_request()),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "an affected NETGEAR device");
