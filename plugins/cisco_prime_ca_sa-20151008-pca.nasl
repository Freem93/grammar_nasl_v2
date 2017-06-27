#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91342);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/31 17:32:09 $");


  script_cve_id("CVE-2015-6328", "CVE-2015-6331");
  script_bugtraq_id(77051, 77052);
  script_osvdb_id(128675, 128704);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus39887");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62680");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus88380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151008-pca");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151008-pca2");

  script_name(english:"Cisco Prime Collaboration Assurance 10.5.1.x < 10.5.1.58480 Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Assurance device is 10.5.1.x prior to 10.5.1.58480. It
is, therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists in the
    web framework of Cisco Prime Collaboration Assurance
    (PCA) due to incorrect implementation of the access
    control code. An authenticated, remote attacker can
    exploit this, via a specially crafted URL, to retrieve
    arbitrary files from the file system. (CVE-2015-6328)

  - A SQL injection vulnerability exists in the web
    framework of Cisco Prime Collaboration Assurance (PCA)
    due to improper sanitization of user-supplied input
    before using it in SQL queries. An authenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, allowing for the
    manipulation or disclosure of arbitrary data.
    (CVE-2015-6331)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151008-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1caf7cce");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151008-pca2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d34ea30b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 10.5.1.58480 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_assurance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_assurance_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationAssurance/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Assurance";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationAssurance/version");

# We got the version from the WebUI and its not granular enough
if (version == "10" || version == "10.5" || version == "10.5.1")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "10.5.1.58480";

if(version =~ "^10\.5\.1\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
