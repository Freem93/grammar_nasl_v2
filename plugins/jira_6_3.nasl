#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100220);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2017-5983");
  script_bugtraq_id(97379);
  script_osvdb_id(153388, 153389, 153390);
  script_xref(name:"CERT", value:"307983");

  script_name(english:"Atlassian JIRA 4.2.4 < 6.3.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is 4.2.4 or later but
prior to 6.3.0. It is, therefore, affected by multiple vulnerabilities
in the JIRA Workflow Designer plugin :

  - A remote code execution vulnerability exists in the
    Action Message Format (AMF3) deserializer due to
    deriving class instances from java.io.Externalizable
    rather than the AMF3 specification's recommendation of
    flash.utils.IExternalizable. An unauthenticated, remote
    attacker with the ability to spoof or control an RMI
    server connection can exploit this to execute arbitrary
    code. (CVE-2017-5983 / VulnDB 153388)

  - An unspecified flaw exists in the XML Parser and Action
    Message Format (AMF3) deserializer components that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-5983 /
    VulnDB 153389)

  - An XML external entity (XXE) vulnerability exists in the
    XML Parser and Action Message Format (AMF3) deserializer
    components due to improper validation of XML documents
    embedded in AMF3 messages. An unauthenticated, remote 
    attacker can exploit this to disclose sensitive
    information. (CVE-2017-5983 / VulnDB 153390)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://confluence.atlassian.com/jira/jira-security-advisory-2017-03-09-879243455.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53ca783d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 6.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8080);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "4.2.4", "fixed_version" : "6.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
