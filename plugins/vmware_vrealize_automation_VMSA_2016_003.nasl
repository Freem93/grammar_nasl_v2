#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90763);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id("CVE-2015-2344");
  script_osvdb_id(135900);
  script_xref(name:"VMSA", value:"2016-0003");

  script_name(english:"VMware vRealize Automation 6.x < 6.2.4 Unspecified Stored XSS (VMSA-2016-0003)");
  script_summary(english:"Checks the version of VMware vRealize Automation.");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by a stored cross-site-scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Automation application running on the remote host
is 6.x prior to 6.2.4. It is, therefore, affected by an unspecified
stored cross-site scripting vulnerability due to improper validation
of user-supplied input. A remote attacker can exploit this by
convincing a user to follow a specially crafted request, resulting in
the execution of arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0003");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Mar/55");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Automation version 6.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
fix = "6.2.4";

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
  count = get_install_count(app_name:app);

  # and audit out if we don't have either
  if (count == 0)
    audit(AUDIT_NOT_INST, app);

  port = get_http_port(default:5480);
  install = get_single_install(app_name:app, port:port);

  version = install['version'];
  source = build_url2(port:port, qs:install['path']);
}

if (version !~ "^6($|\.)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Fixed version", fix,
      "Source", source
    ),
    ordered_fields:make_list("Installed version", "Fixed version", "Source")
  );
  security_report_v4(port:port, severity:SECURITY_NOTE, xss:TRUE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
