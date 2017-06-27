#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71891);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-4822", "CVE-2013-4823");
  script_bugtraq_id(62895, 62897);
  script_osvdb_id(98247, 98248);

  script_name(english:"HP Intelligent Management Center Branch Intelligent Management Module Multiple Vulnerabilities");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the HP Branch Intelligent Management System module
on the remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the HP Intelligent Management Center Branch Intelligent
Management System module on the remote host is a version prior to 5.2
E0401 and is potentially affected by multiple vulnerabilities :

  - The 'bimsDownload' servlet is not protected by
    authentication and could be used to access any file on
    the system remotely. (CVE-2013-4823)

  - The 'UploadServlet' in the BIM module allows
    unauthenticated users to remotely upload arbitrary files
    to specific locations on the host. (CVE-2013-4822)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-238/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-239/");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03943425
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccb23e43");
  script_set_attribute(attribute:"solution", value:"Upgrade the iMC BIMs module to version 5.2 E0401 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"HP Intelligent Management Center BIMS UploadServlet File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Intelligent Management Center BIMS UploadServlet Directory Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
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

# Versions 5.1 E0201 and earlier are affected
if (version =~ '^([0-4]\\.|5\\.(0\\-|1\\-E0([0-9]{1,2}|[01][0-9]{2}|20[01])([^0-9]|$)))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2-E0401' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center BIMS Component', port, version);
