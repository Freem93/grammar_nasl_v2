#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73103);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/08 15:44:53 $");

  script_cve_id("CVE-2013-4054", "CVE-2013-5780");
  script_bugtraq_id(65897, 63115);
  script_osvdb_id(98562, 103867, 104223);

  script_name(english:"IBM WebSphere MQ 7.1 < 7.1.0.5 / 7.5 < 7.5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere MQ server 7.1 / 7.5 installed on the
remote Windows host is missing fix pack 7.1.0.5 / 7.5.0.3 or later. It
is, therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists due to a
    failure to sanitize user-supplied input in the MQ
    Telemetry component, resulting in path traversal outside
    of a restricted path. A remote attacker can exploit
    this, using a URI request, to view any file readable by
    the 'mqm' user. (CVE-2013-4054)

  - An unspecified information disclosure vulnerability
    exists in IBM Java related to the Libraries component.
    A remote attacker can exploit this to obtain sensitive
    information. (CVE-2013-5780)

Note that the fix list for fix pack 7.5.0.3 shows that several APARs
have a security or integrity exposure (IC93986, IC94287, IC94453,
IC94752, IC97555). It is not known whether any of these APARs
correspond with the information disclosure vulnerability in the
Telemetry component or to what extent they represent actual security
issues.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_websphere_mq_telemetry_security_vulnerability_potential_improper_access_control_via_specially_formed_uri_request?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af978a19");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_ibm_websphere_mq_is_affected_by_a_vulnerability_in_the_ibm_jre_cve_2013_57801?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8563017");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21664550");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21671933");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27038184#7503");
  script_set_attribute(attribute:"solution", value:"Apply fix pack 7.1.0.5 / 7.5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
fix      = FALSE;
fixes    = make_array(
  "^7\.1\.", "7.1.0.5",
  "^7\.5\.", "7.5.0.3"
);

# Find the fix for our version
foreach fixcheck (keys(fixes))
{
  if(version =~ fixcheck)
  {
    fix = fixes[fixcheck];
    break;
  }
}

# Version not affected
if(!fix)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
