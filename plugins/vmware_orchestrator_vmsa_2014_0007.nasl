#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78671);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:34:51 $");

  script_cve_id("CVE-2014-0050");
  script_bugtraq_id(65400);
  script_osvdb_id(102945);
  script_xref(name:"VMSA", value:"2014-0007");

  script_name(english:"VMware vCenter Orchestrator 5.5.x < 5.5.2 DoS (VMSA-2014-0007)");
  script_summary(english:"Checks the version of VMware vCenter Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Orchestrator installed on the remote
host is 5.5.x prior to 5.5.2. It is, therefore, affected by a denial
of service vulnerability due to an error that exists in the included
Apache Tomcat version related to handling 'Content-Type' HTTP headers
and multipart requests.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0007");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Orchestrator 5.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_orchestrator");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_orchestrator_installed.nbin");
  script_require_keys("installed_sw/VMware vCenter Orchestrator");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "VMware vCenter Orchestrator";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
verui = install['VerUI'];
path  = install['path'];

if (version =~ '^5\\.5\\.')
{
  build = install['Build'];
  if (empty_or_null(build)) exit(1, 'The ' + app_name + ' build number is missing.');

  if (int(build) < 1951762)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + verui +
        '\n  Fixed version     : 5.5.2 Build 1951762' +
        '\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
    exit(0);
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
