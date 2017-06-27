#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70073);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2010-0143", "CVE-2010-0144", "CVE-2010-0145");
  script_bugtraq_id(38168, 38169, 38170);
  script_osvdb_id(62285, 62286, 62287);
  script_xref(name:"IAVA", value:"2010-A-0021");

  script_name(english:"Cisco IronPort PostX < 6.2.9.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco IronPort PostX");

  script_set_attribute(attribute:"synopsis", value:
"The remote device runs a service that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IronPort PostX on the remote device is a version
prior to 6.2.9.1.  As such, it is affected by multiple vulnerabilities :

  - An unspecified vulnerability in the administrative
    interface in the embedded HTTPS server allows remote
    attackers to read arbitrary files via unknown vectors.
    (CVE-2010-0143)

  - An unspecified vulnerability in the WebSafe
    DistributorServlet in the embedded HTTPS server allows
    remote attackers to read arbitrary files via unknown
    vectors. (CVE-2010-0144)

  - An unspecified vulnerability in the embedded HTTPS
    server allows remote attackers to execute arbitrary code
    via unknown vectors. (CVE-2010-0145)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a523d7e2");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cb89c45");
  script_set_attribute(attribute:"solution", value:"Contact Cisco IronPort technical support for update information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:ironport_postx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("PostX" >!< banner) exit(0, "The banner from the SMTP server listening on port "+port+" is not from PostX.");

matches = eregmatch(pattern:"\(.*?PostX.*?([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?).*?\)", string:banner);
if (isnull(matches[1])) exit(1, "Failed to determine the version of PostX based on the banner from the SMTP server listening on port "+port+".");
version = matches[1];

# only do the version check when paranoid since mitigations that do not
# affect the SMTP banner are available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed = "6.2.9.1";

if (ver_compare(ver:version, fix:fixed, strict:FALSE) != -1) audit(AUDIT_LISTEN_NOT_VULN, "PostX", port, version);

if (report_verbosity > 0)
{
  report =
  '\n  Version source    : ' + banner +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed +
  '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port:port);

