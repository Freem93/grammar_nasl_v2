#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91343);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/31 17:32:09 $");
  

  script_cve_id("CVE-2016-1392");
  script_osvdb_id(137959);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu34121");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160503-pca");

  script_name(english:"Cisco Prime Collaboration Assurance 10.5.x / 10.6.x / 11.0.x / 11.1.x < 11.1.66527 Open Redirect (cisco-sa-20160503-pca)");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is affected by an open redirect
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Assurance device is 10.5.x, 10.6.x, 11.0.x, or 11.1.x
prior to 11.1.66527. It is, therefore, affected by an open redirect
vulnerability in the web interface component due to improper
sanitization of user-supplied input to HTTP request parameters. An
unauthenticated, remote attacker can exploit this, by convincing a
user to click a specially crafted link, to redirect a user to a
malicious website.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160503-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e613838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 11.1.66527 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
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
if (version == "10" || version == "11" || version == "11.1")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "11.1.66527";

if(
  version =~ "^(10\.[56]|11\.[01])([^0-9]|$)" &&
  ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
