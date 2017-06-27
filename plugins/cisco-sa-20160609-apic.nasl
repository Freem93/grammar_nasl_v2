#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91730);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/06/21 19:35:30 $");

  script_cve_id("CVE-2016-1420");
  script_osvdb_id(139610);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz72347");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160609-apic");

  script_name(english:"Cisco APIC < 1.3(2f) Binary File Installation Handling Local Privilege Escalation");
  script_summary(english:"Checks the APIC version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system running on the remote host is affected by
a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Application
Policy Infrastructure Controller (APIC) software running on the remote 
host is prior to 1.3(2f). It is, therefore, affected by a local
privilege escalation vulnerability due to insecure permissions set for
binary files during the installation process. A local attacker can
exploit this to gain root-level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160609-apic
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f00f4f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco APIC version 1.3(2f) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco APIC Software";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];
fix = '1.3(2f)';
vuln = FALSE;

# Affects all < 1.3(2f)
# Only versions of format 1.x([0-9][a-z]) are released to customers
if (
  ver =~ "^1\.[0-2]\([0-9][a-z]\)" ||
  ver =~ "^1\.3\(1[a-z]\)" ||
  ver =~ "^1\.3\(2[a-e]\)"
  )
  vuln = TRUE;
report = NULL;

if (vuln)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
