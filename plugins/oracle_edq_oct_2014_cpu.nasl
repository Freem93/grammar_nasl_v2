#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78749);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2014-0114", "CVE-2014-0119");
  script_bugtraq_id(67121, 67669);
  script_osvdb_id(106409, 107453);

  script_name(english:"Oracle Enterprise Data Quality Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the versions.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Data Quality running on the remote
host is affected by multiple vulnerabilities :

  - A flaw in Apache Commons BeanUtils allows a remote
    attacker to execute arbitrary code by manipulating the
    ClassLoader. (CVE-2014-0114)

  - A flaw in Apache Tomcat allows a remote attacker to
    replace the XML parsers and thereby gain access to
    sensitive information. (CVE-2014-0119)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_edq_director_detect.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Data Quality Director");
  script_require_ports("Services/www", 9002);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

port = get_http_port(default:9002);

app_name = "Oracle Enterprise Data Quality Director";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE, port:port);
version = install["version"];
path = install["path"];

item = eregmatch(pattern:"^([0-9.]+[0-9])\.?([^0-9.]|$)", string:version);
# should never happen
if (isnull(item) || isnull(item[1])) exit(1, "Error parsing version string : " + version);
chk_ver = item[1];

fix = "";

if (
  chk_ver =~ "^9\.0\." &&
  ver_compare(ver:chk_ver, fix:"9.0.11", strict:FALSE) == -1
) fix = "9.0.11";

# Looks like Oracle mis-published the patch for this
# Leaving check out until the correct patch is published
#if (version =~ "^8\.1\." &&
#   ver_compare(ver:version, fix:"8.1.12", strict:FALSE) == -1)
#  fix = "8.1.12";

if (fix != "")
{
  if (report_verbosity > 0)
  {
    report += 
      '\n  URL               : ' + build_url(port:port, qs:path) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
