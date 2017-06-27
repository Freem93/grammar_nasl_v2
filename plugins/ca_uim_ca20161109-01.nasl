#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95662);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_cve_id(
    "CVE-2016-5803",
    "CVE-2016-9164", 
    "CVE-2016-9165"
  );
  script_bugtraq_id(
    94243,
    94257,
    94257
  );
  script_osvdb_id(
    147023, 
    147024,
    147025
  );
  script_xref(name:"ICSA", value:"16-315-01");
  script_xref(name:"IAVB", value:"2016-B-0184");
  script_xref(name:"ZDI", value:"ZDI-16-605");
  script_xref(name:"ZDI", value:"ZDI-16-606");
  script_xref(name:"ZDI", value:"ZDI-16-607");

  script_name(english:"CA Unified Infrastructure Management < 8.4 SP2 Multiple Information Disclosure Vulnerabilities (CA20161109-01)");
  script_summary(english:"Checks the CA UIM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number from the CA Unified
Management Portal (UMP), the CA Unified Infrastructure Management
(UIM) application running on the remote host is prior to 8.4 SP2. It
is, therefore, affected by multiple information disclosure
vulnerabilities :

  - An information disclosure vulnerability exists in the
    download_lar.jsp servlet due to a flaw that allows
    traversing outside of a restricted path. An
    unauthenticated, remote attacker can exploit this
    vulnerability, via a specially crafted request, to read
    arbitrary files. (CVE-2016-5803)

  - An information disclosure vulnerability exists in the
    diag.jsp servlet due to a flaw that allows traversing
    outside of a restricted path. An unauthenticated, remote
    attacker can exploit this vulnerability, via a specially
    crafted request, to read arbitrary files.
    (CVE-2016-9164)

  - An information disclosure vulnerability exists in the
    get_sessions servlet that allows an unauthenticated,
    remote attacker to disclose session IDs via a specially
    crafted request. The session ID can then be used to
    hijack a user's session. (CVE-2016-9165)");
  # http://www.ca.com/us/services-support/ca-support/ca-support-online/product-content/recommended-reading/security-notices/ca20161109-01-security-notice-for-ca-unified-infrastructure-mgmt.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019b0f45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CA UIM version 8.4 SP2 or later. The vendor recommends
upgrading to the latest version (8.47) if possible.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ca:unified_infrastructure_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ca_ump_detect.nbin");
  script_require_keys("installed_sw/CA UMP", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product = "CA Unified Infrastructure Management";
ump = "CA UMP";

install = get_single_install(app_name:ump, exit_if_unknown_ver:TRUE, combined:TRUE);
ver = install['version'];
port = install['port'];
if(empty_or_null(port)) port = 0;

fix = "8.4.2";
# UMP shows versions in format 8.4.2/8.4.7
# But the versions listed in advisories/documentation
# Look like 8.42/8.47.
# Where 8.42 = 8.4 sp2, and 8.47 is just 8.47.
if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  items = make_array("Installed version", ver,
                     "Fixed version", fix
                    );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  report += 
  '\nNote: The version was determined by checking the Unified Management '+
  '\n      Portal instance running on this host; however, it may not'+
  '\n      directly reflect the version of the Unified Infrastructure'+
  '\n      Management instance.\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_VER_NOT_VULN, product, ver);
