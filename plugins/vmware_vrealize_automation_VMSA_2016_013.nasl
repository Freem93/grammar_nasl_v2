#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93191);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2016-5335", "CVE-2016-5336");
  script_bugtraq_id(92607, 92608);
  script_osvdb_id(143441, 143442);
  script_xref(name:"VMSA", value:"2016-0013");

  script_name(english:"VMware vRealize Automation 7.0.x < 7.1 Multiple Vulnerabilities (VMSA-2016-0013)");
  script_summary(english:"Checks the version of VMware vRealize Automation.");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Automation application running on the remote host
is version 7.0.x prior to 7.1. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified flaw exists that allows a local attacker
    to elevate privileges from a low-privileged account to
    root access. (CVE-2016-5335)
    
  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to execute code and
    thereby gain access to a low privilege account on the
    device. No other details are available. (CVE-2016-5336)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0013");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Automation version 7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "vmware_vrealize_automation_webui_detect.nbin");
  script_require_ports("Host/VMware vRealize Automation/Version", "installed_sw/VMware vRealize Automation");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app = "VMware vRealize Automation";
fix = "7.1";

# first we try using local info from ssh
version = get_kb_item("Host/" + app + "/Version");
if (!isnull(version) && version != UNKNOWN_VER)
{
  port = 0;
  source = "SSH";
}
else
{
  # then we fall back to using web interface info
  get_install_count(app_name:app, exit_if_zero:TRUE);

  port = get_http_port(default:5480);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

  version = install['version'];
  source = build_url2(port:port, qs:install['path']);
}

if (version =~ "^7\.0(\.[0-9]+)?$")
{
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Fixed version", fix,
      "Source", source
    ),
    ordered_fields:make_list("Installed version", "Fixed version", "Source")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
