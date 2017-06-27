#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72830);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_bugtraq_id(
    67178,
    67201,
    68889
  );
  script_osvdb_id(
    103226,
    103227,
    103228,
    103229,
    103230,
    103231,
    103232,
    103233,
    106530
  );
  script_xref(name:"EDB-ID", value:"31617");
  script_xref(name:"EDB-ID", value:"33138");
  script_xref(name:"EDB-ID", value:"33150");
  script_xref(name:"EDB-ID", value:"34149");

  script_name(english:"NETGEAR DGN2200 Multiple Vulnerabilities");
  script_summary(english:"Checks if the remote device is a NETGEAR DGN2200.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine that the remote device is a NETGEAR
DGN2200. This device is affected by multiple vulnerabilities, the
worst of which allow an unauthenticated, adjacent attacker to gain
root telnet access to the device.");
  script_set_attribute(attribute:"solution", value:
"Discontinue use of this device as it is no longer supported by
NETGEAR.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:netgear:dgn2200");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

res = http_send_recv3(method:"GET", port:port, item:"/currentsetting.htm");

if ("Model=DGN2200" >< res[2])
{
  report = '\nDevice information : \n\n' + res[2] + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, "a NETGEAR DGN2200");
