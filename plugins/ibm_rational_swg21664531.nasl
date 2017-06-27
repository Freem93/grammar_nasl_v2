#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77607);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/10 21:05:22 $");

  script_cve_id("CVE-2013-5459");
  script_bugtraq_id(66987);
  script_osvdb_id(106095);

  script_name(english:"IBM Rational Software Architect Design Manager and Rhapsody Design Manager < 4.0.6000 Unspecified Vulnerability");
  script_summary(english:"Checks the version of RSA/RDM.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Rational Software
Architect Design Manager or IBM Rhapsody Design Manager that is
affected by an unspecified data integrity vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21664531");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational Software Architect Design Manager / Rhapsody
Design Manager version 4.0.6000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_software_architect_design_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rhapsody_design_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_enum_products.nbin");
  script_require_ports("installed_sw/Design Management for IBM Rational Software Architect", "installed_sw/Design Management for IBM Rational Rhapsody");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = branch(
  make_list(
    "Design Management for IBM Rational Software Architect",
    "Design Management for IBM Rational Rhapsody"
  )
);

get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name);
path = install['path'];
version = install['version'];

vuln_versions = make_list(
  "3.0", 
  "3.0.0.1000", 
  "3.0.1000", 
  "4.0", 
  "4.0.1000", 
  "4.0.2000", 
  "4.0.3000", 
  "4.0.4000", 
  "4.0.5000"
);
fix = "4.0.6000";

vuln = FALSE;
foreach vuln_version (vuln_versions)
{
  if (ver_compare(ver:version, fix:vuln_version, strict:FALSE) == 0)
  {
    vuln = TRUE;
    break;
  }
}

if (vuln)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Application       : ' + app_name +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_note(extra:report, port:port);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
