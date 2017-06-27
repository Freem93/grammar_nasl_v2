#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90711);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2016-2076");
  script_osvdb_id(137167);
  script_xref(name:"VMSA", value:"2016-0004");

  script_name(english:"VMware vCloud Director 5.5.x < 5.5.6 Client Integration Plugin Session Hijacking (VMSA-2016-0004)");
  script_summary(english:"Checks the version of VMware vCloud Director.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
a session hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCloud Director installed on the remote host is
5.5.x prior to 5.5.6. It is, therefore, affected by a flaw in the
VMware Client Integration Plugin due to a failure to handle session
content in a secure manner. A remote attacker can exploit this, by
convincing a user to visit a malicious web page, to conduct a session
hijacking attack. It can also be exploited to carry out a
man-in-the-middle attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCloud Director version 5.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");
build = get_kb_item_or_exit("Host/VMware vCloud Director/Build");

port = 0;
vuln_ver = "5.5.5";
fixed_ver_string = "5.5.6 Build 3764659";

if (version != vuln_ver)
  audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCloud Director', version + ' Build ' + build);

report = report_items_str(
  report_items:make_array(
    "Installed version", version + ' Build ' + build,
    "Fixed version", fixed_ver_string
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
