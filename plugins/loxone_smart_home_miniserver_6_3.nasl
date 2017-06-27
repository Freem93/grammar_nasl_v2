#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81810);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_bugtraq_id(72804);
  script_osvdb_id(
    118940,
    118941,
    118942,
    118943,
    118944,
    118945,
    118946,
    118947
  );

  script_name(english:"Loxone Smart Home Miniserver < 6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Loxone Smart Home Miniserver
device is a version prior to 6.3. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    the device transmitting all data in cleartext. A remote
    man-in-the-middle attacker can read the transmitted
    data, resulting in the disclosure of device credentials.
    (VulnDB 118940)

  - A cross-frame scripting vulnerability exists due to
    improper restriction of JavaScript from one web page
    accessing another when the page originates from
    different domains. A remote attacker can exploit this to
    use one web page to load content from another,
    concealing the origin of a web site. (VulnDB 118941)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to improper validation of HTTP requests. (VulnDB
    118942)

  - An HTTP response splitting vulnerability exists due to
    a failure to properly validate input appended to the
    response header. This allows an attacker to insert
    arbitrary HTTP headers to manipulate cookies and
    authentication status. (VulnDB 118943)

  - Multiple reflected cross-site scripting vulnerabilities
    exist due to improper validation of HTTP requests.
    (VulnDB 118944)

  - A stored cross-site scripting vulnerability exists due
    to improper validation of the content in the description
    field of a new task. (118945)

  - An information disclosure vulnerability exists due to
    the program storing user credentials in an insecure
    manner. The credentials are encrypted, but the key used
    for their decryption may be requested without
    authentication. (VulnDB 118946)

  - Multiple denial of service vulnerabilities exist that
    can be exploited via SYN floods and malformed HTTP
    requests. (VulnDB 118947)

Note that Nessus has not tested for these issues but has instead
relied only on the devices's self-reported version number.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150227-0_Loxone_Smart_Home_Multiple_Vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d49071d7");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Feb/99");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Loxone Smart Home Miniserver firmware to version 6.3 or
later.

Note that the two information disclosure vulnerabilities (VulnDB 118940
/ 118946) still exist in firmware version 6.3. We are currently
unaware of a solution for these issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:loxone:smart_home_miniserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("loxone_smart_home_miniserver_detect.nbin");
  script_require_keys("installed_sw/Loxone Smart Home Miniserver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Loxone Smart Home Miniserver";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80, embedded:TRUE);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
source  = install['Source'];
fix     = "6.3.0.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source  +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix     +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
