#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59736);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/08/08 04:47:46 $");

  script_cve_id("CVE-2012-0516", "CVE-2012-1738");
  script_bugtraq_id(53133, 54515);
  script_osvdb_id(81440, 81545, 81546, 83974);

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the admin console.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly Sun Java System Web Server) running on the remote host is
7.0.x prior to 7.0.15. It is, therefore, affected by the following
vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist due
    to parameter validation errors that occur when input is
    submitted to admingui scripts 'cchelp2/Masthead.jsp',
    'version/Masthead.jsp', and 'cchelp2/Navigator.jsp'. A
    remote attacker, using a crafted URL, can exploit these
    to execute arbitrary script code in the user's browser
    in the context of the session between the browser and
    the server. (CVE-2012-0516)

  - An unspecified error exists in the Web Server component
    that can allow denial of service attacks.
    (CVE-2012-1738)

Note that Oracle states that bug 12919334 'WS7: RANGE HEADER DOS
VULNERABILITY' could not be reproduced.");
  # http://www.myvuln.com/2012/04/oracle-iplanet-web-server-709-multiple.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b889755f");
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/cd/E18958_01/doc.70/e18789/chapter.htm");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html#AppendixSUNS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28826476");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server 7.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server/");
  
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "Oracle iPlanet Web Server";
port = get_http_port(default:8989);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = "7.0.15";
min = "7.0";

if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + app_name +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 7.0.15' +
        '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
