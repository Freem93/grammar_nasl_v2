#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100296);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/19 17:26:31 $");

  script_cve_id(
    "CVE-2017-4965",
    "CVE-2017-4966",
    "CVE-2017-4967"
  );
  script_bugtraq_id(
    98394,
    98405,
    98406
  );
  script_osvdb_id(
    154742,
    154743,
    154744
  );
  script_xref(name:"IAVB", value:"2017-B-0057");

  script_name(english:"Pivotal RabbitMQ Management Plugin 3.4.x / 3.5.x / 3.6.x < 3.6.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of RabbitMQ.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pivotal
RabbitMQ running on the remote web server is 3.4.x, 3.5.x, or 3.6.x
prior to 3.6.9. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the Management user interface due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted request, to execute arbitrary script code in
    a user's browser session. (CVE-2017-4965, CVE-2017-4967)

  - An information disclosure vulnerability exists in
    credential caching due to credentials being cached
    locally in the browser and not expiring. A local
    attacker can exploit this, via a chained attack, to
    disclose user credentials. (CVE-2017-4966)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://github.com/rabbitmq/rabbitmq-server/releases/tag/rabbitmq_v3_6_9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90b10df1");
  script_set_attribute(attribute:"see_also", value:"https://pivotal.io/security/cve-2017-4965");
  script_set_attribute(attribute:"see_also", value:"https://pivotal.io/security/cve-2017-4966");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("pivotal_rabbitmq_mgmt_detect.nbin");
  script_require_keys("installed_sw/Pivotal RabbitMQ Management Plugin");
  script_require_ports("Services/www", 8080, 15672);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:15672);

app_info = vcf::get_app_info(app:"Pivotal RabbitMQ Management Plugin", port:port, webapp:true);
vcf::check_granularity(app_info:app_info, sig_segments:2);
constraints = [{ "min_version" : "3.4", "fixed_version" : "3.6.9" }];
flags = {"xss":TRUE};

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
