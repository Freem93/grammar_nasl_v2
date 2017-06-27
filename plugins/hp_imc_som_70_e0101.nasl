#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71892);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-4824", "CVE-2013-4826");
  script_bugtraq_id(62898, 62902);
  script_osvdb_id(98249, 98251);

  script_name(english:"HP Intelligent Management Center SOM Module < 7.0 E0101 Multiple Vulnerabilities");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the HP Intelligent Management Center Service Operation
Management Software module on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the HP Intelligent Management Center Service Operation
Management Software Module on the remote is prior to 7.0 E0101.  It is
therefore, potentially affected by multiple vulnerabilities :

  - An authentication bypass vulnerability exists in the
    'euAccountService' servlet that allows arbitrary users
    to be created without authentication. (CVE-2013-4824)

  - An information disclosure vulnerability exists in the
    'sdFileDownload' servlet that allows for arbitrary file
    access. (CVE-2013-4826)"
  );
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-c03943547-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1cc20f8");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-243/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-242/");
  script_set_attribute(attribute:"solution", value:"Upgrade the iMC SOM module to version 7.0 E0101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
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

version = get_kb_item_or_exit('hp/hp_imc/' + port + '/components/iMC-SOM-SERVICEDESK/version');

# Versions 5.2 E0401 and earlier are affected
if (version =~ '^([0-4]\\.|5\\.(0\\-|1\\-|2\\-E0([0-9]{1,2}|[0-3][0-9]{2}|40[01])([^0-9]|$)))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0-E0101' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center SOM Component', port, version);
