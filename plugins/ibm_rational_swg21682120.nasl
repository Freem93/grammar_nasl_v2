#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79384);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:26 $");

  script_cve_id("CVE-2014-3037");
  script_bugtraq_id(69658);
  script_osvdb_id(110791);

  script_name(english:"IBM Rational Software Architect Design Manager / Engineering Lifecycle Manager / Rhapsody Design Manager < 4.0.7 XSRF");
  script_summary(english:"Checks the version of RSA/RDM/RELM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self reported version, the install of Rational
Engineering Lifecycle Manager, Rational Software Architect Design
Manager, and/or Rhapsody Design Manager on the remote host is affected
by a cross-site request forgery in the IBM Configuration Management
Application (VVC) component due to improper validation of
user-supplied data. An attacker can exploit this vulnerability by
convincing an authenticated user to visit a malicious website and
hijacking the authentication via a malformed HTTP request, allowing
the attacker to perform cross-site scripting attacks, web cache
poisoning, and other malicious activities.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational Software Architect Design Manager /
Engineering Lifecycle Manager / Rhapsody Design Manager version 4.0.7,
5.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_software_architect_design_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_rhapsody_design_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_engineering_lifecycle_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_enum_products.nbin");
  script_require_ports(
    "installed_sw/Design Management for IBM Rational Software Architect",
    "installed_sw/Design Management for IBM Rational Rhapsody",
    "installed_sw/Rational Engineering Lifecycle Manager"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

vuln_matrix = make_array(
    "Design Management for IBM Rational Software Architect", make_list(
      "3.0",
      "3.0.0.1000",
      "3.0.1000",
      "4.0",
      "4.0.1000",
      "4.0.2000",
      "4.0.3000",
      "4.0.4000",
      "4.0.5000",
      "4.0.6000",
      "5.0"
    ),
    "Design Management for IBM Rational Rhapsody", make_list(
      "3.0",
      "3.0.0.1000",
      "3.0.1000",
      "4.0",
      "4.0.1000",
      "4.0.2000",
      "4.0.3000",
      "4.0.4000",
      "4.0.5000",
      "4.0.6000",
      "5.0"
    ),
    "Rational Engineering Lifecycle Manager", make_list(
      "1.0",
      "1.0.0.1000",
      "4.0.3000",
      "4.0.4000",
      "4.0.5000",
      "4.0.6000",
      "5.0"
    )
);

# Check each product in a different thread
app_name = branch(
  make_list(
    "Design Management for IBM Rational Software Architect",
    "Design Management for IBM Rational Rhapsody",
    "Rational Engineering Lifecycle Manager"
  )
);

install = get_single_install(app_name:app_name);
path = install['path'];
version = install['version'];

fix = "4.0.7000 / 5.0.1000";

vuln = FALSE;
foreach vuln_version (vuln_matrix[app_name])
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
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Application       : ' + app_name +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
