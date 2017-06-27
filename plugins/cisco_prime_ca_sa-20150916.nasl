#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86152);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/19 18:41:38 $");

  script_cve_id("CVE-2015-4304", "CVE-2015-4305", "CVE-2015-4306");
  script_bugtraq_id(76757, 76759, 76761);
  script_osvdb_id(127644, 127645, 127646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62656");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus88343");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus88334");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150916-pca");

  script_name(english:"Cisco Prime Collaboration Assurance Multiple Vulnerabilities (cisco-sa-20100217-csa)");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Assurance device is prior to 10.5.1.53684 or is in the
10.6 release branch. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists in the web
    framework due to improper implementation of
    authorization and access controls. An authenticated,
    remote attacker can exploit this, via a crafted URL
    request, to access higher-privileged functions that are
    normally restricted to administrative users only.
    (CVE-2015-4304)

  - An information disclosure vulnerability exists in the
    web framework due to improper implementation of
    authorization and access controls. An authenticated,
    remote attacker can exploit this, via a crafted URL
    request, to access information about devices imported
    into the system database, including SNMP community
    strings and administrative credentials. (CVE-2015-4305)

  - An information disclosure vulnerability exists in the
    web framework due to improper implementation of
    authorization and access controls. An authenticated,
    remote attacker can exploit this, via a crafted URL
    request, to access information about users who are
    logged in to the system, including users' session
    identifiers. The identifiers can be used by an attacker
    to impersonate any user, including administrative users.
    (CVE-2015-4306)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150916-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d42dd8ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 10.5.1.53684 or
11.0. Note that there is no fix for version 10.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_assurance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_assurance_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationAssurance/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Assurance";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationAssurance/version");

fix = false;

# We got the version from the WebUI and its not granular enough
if (version == "10.5" || version == "10.5.1")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

if (version =~ "^10\.6($|\.)")
  fix = "11.0\nNote that there is no fix for version 10.6, upgrade to at least 11.0.";

if (ver_compare(ver:version, fix:"9.0.0",  strict:FALSE) >= 0 && 
    ver_compare(ver:version, fix:"10.5.0", strict:FALSE) <= 0)
  fix = "10.5.1.53684";

if(version =~ "^10\.5\.1\." && ver_compare(ver:version, fix:"10.5.1.53684", strict:FALSE) < 0)
  fix = "10.5.1.53684";

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
