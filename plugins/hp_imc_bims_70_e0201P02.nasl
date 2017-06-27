#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76621);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id(
    "CVE-2014-2618",
    "CVE-2014-2619",
    "CVE-2014-2620",
    "CVE-2014-2621",
    "CVE-2014-2622"
  );
  script_bugtraq_id(68540, 68543, 68544, 68546, 68547);
  script_osvdb_id(109168, 109169, 109170, 109171, 109172);
  script_xref(name:"HP", value:"emr_na-c04369484");
  script_xref(name:"HP", value:"HPSBHF02913");
  script_xref(name:"HP", value:"SSRT101406");
  script_xref(name:"HP", value:"SSRT101408");
  script_xref(name:"HP", value:"SSRT101409");
  script_xref(name:"HP", value:"SSRT101410");
  script_xref(name:"HP", value:"SSRT101552");

  script_name(english:"HP Intelligent Management Center Branch Intelligent Management Module 7.x < 7.0-E0201P02 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Intelligent Management Center Branch Intelligent Management.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the HP Branch Intelligent Management System module on
the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the HP Intelligent Management Center Branch Intelligent
Management System (BIMS) module on the remote host is version 7.x
prior to 7.0-E0201P02 and has multiple vulnerabilities that could
allow a remote attacker to access sensitive information via
unspecified vectors.");
  # https://h20564.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04369484
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3918530c");
  script_set_attribute(attribute:"solution", value:"Upgrade the iMC BIMs module to version 7.0-E0201P02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:imc_branch_intelligent_management_system_software_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies('hp_imc_detect.nbin');
  script_require_ports('Services/activemq', 61616);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to use
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);

version = get_kb_item_or_exit('hp/hp_imc/' + port + '/components/iMC-BIMS/version');

# Only Version 7.0 known to be affected
if (version !~ "^7\.0") audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center Branch Intelligent Management module', port, version);

verparts = split(version, sep:"-");
patchver = FALSE;
# Versions 7.0 affected before E0201P02, remove letters in patch version (if patched)
if (max_index(verparts) > 1) patchver = ereg_replace(string:verparts[1], pattern:"[A-Z]", replace:"");
# All versions have the "dash" : i.e. 7.0-E202P03
# if it doesn't have a dash we got a weird version somehow.
if (!patchver) audit(AUDIT_UNKNOWN_APP_VER, 'HP Intelligent Management Center Branch Intelligent Management module');

if (ver_compare(fix:"020102", ver:patchver, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0-E0201P02' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center Branch Intelligent Management module', port, version);
