#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51138);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/08 04:47:46 $");

  script_cve_id(
    "CVE-2010-3512",
    "CVE-2010-3514",
    "CVE-2010-3544",
    "CVE-2010-3545"
  );
  script_bugtraq_id(43977, 43984, 44004, 44034);
  script_osvdb_id(70024, 70025, 70026, 70027);
  script_xref(name:"EDB-ID", value:"15290");

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the admin console");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly known as Sun Java System Web Server) running on the remote
host is 7.0.x prior to 7.0.9. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified file disclosure vulnerability exists in
    the WebDAV component. (CVE-2010-3512)

  - An HTTP response splitting vulnerability exists in the
    web container component due to a failure to sanitize
    HTTP response headers of CR / LF characters. 
    (CVE-2010-3514)

  - A cross-site request forgery vulnerability exists in
    the management console that can allow an attacker to
    stop an arbitrary server instance. (CVE-2010-3544)

  - An unspecified flaw exists in the administration
    component that allows a remote attacker to impact
    confidentiality and integrity via unknown vectors.
    (CVE-2010-3545)");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN50133036/index.html"  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2010-175626.html#AppendixSUNS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ad07b4e");
  script_set_attribute(attribute:"solution", value:
  "Upgrade to Oracle iPlanet Web Server 7.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

fix = "7.0.9";
min = "7.0";

if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
  )
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
    set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + app_name +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 7.0.9' +
        '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
