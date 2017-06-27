#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/18 14:17:41 $");

  script_cve_id(
    "CVE-2017-7484",
    "CVE-2017-7485",
    "CVE-2017-7486"
  );
  script_bugtraq_id(
    98459,
    98460,
    98461
  );
  script_osvdb_id(
    157414,
    157415,
    157416
  );
  script_xref(name:"IAVB", value:"2017-B-0056");

  script_name(english:"PostgreSQL 9.2.x < 9.2.21 / 9.3.x < 9.3.17 / 9.4.x < 9.4.12 / 9.5.x < 9.5.7 / 9.6.x < 9.6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.2.x prior
to 9.2.21, 9.3.x prior to 9.3.17, 9.4.x prior to 9.4.12, 9.5.x prior
to 9.5.7, or 9.6.x prior to 9.6.3. It is, therefore, affected by
multiple vulnerabilities :

  - A information disclosure vulnerability exists in
    unspecified selectivity estimation functions due to
    improper checking of user privileges before providing
    information from pg_statistics. An authenticated, remote
    attacker can exploit this to disclose potentially
    sensitive information from restricted tables.
    (CVE-2017-7484)

  - A flaw exists because the PGREQUIRESSL environment
    variable setting is not properly honored, which results
    in a failure to require appropriate SSL/TLS connections.
    A man-in-the-middle attacker can exploit this to cause
    an insecure, non-SSL/TLS connection between a client and
    and a server. Note that version 9.2.x is not affected by
    this vulnerability. (CVE-2017-7485)

  - A information disclosure vulnerability exists in the
    pg_user_mappings view that allows access to user
    mappings which may contain passwords that have persisted
    from the CREATE USER MAPPING command. An authenticated,
    remote attacker who has USAGE privilege on the
    associated foreign server can exploit this to disclose
    foreign server passwords. (CVE-2017-7486)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1746/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-2-21.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-3-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-4-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-5-7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-6-3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.2.21 / 9.3.17 / 9.4.12 / 9.5.7 / 9.6.3
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("vcf.inc");
include("backport.inc");
port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

kb_base = "database/"+port+"/postgresql/";
app_info = vcf::get_app_info(app:"PostgreSQL", port:port, kb_ver:kb_base+"version", kb_backport:kb_base+"backported", service:TRUE);

#  9.2.21 / 9.3.17 / 9.4.12 / 9.5.7 / 9.6.3
constraints = [
  { "min_version" : "9.2", "fixed_version" : "9.2.21" },
  { "min_version" : "9.3", "fixed_version" : "9.3.17" },
  { "min_version" : "9.4", "fixed_version" : "9.4.12" },
  { "min_version" : "9.5", "fixed_version" : "9.5.7" },
  { "min_version" : "9.6", "fixed_version" : "9.6.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
