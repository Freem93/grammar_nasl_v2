# (C) Tenable Network Security, Inc.

include("compat.inc");

if (description)
{
  script_id(95441);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2016-7462");
  script_bugtraq_id(94351);
  script_osvdb_id(147403);
  script_xref(name:"TRA", value:"TRA-2016-34");
  script_xref(name:"IAVB", value:"2016-B-0175");
  script_xref(name:"VMSA", value:"2016-0020");

  script_name(english:"VMware vRealize Operations Manager ver 6.x < 6.40 Suite API CollectorHttpRelayController RelayRequest Object DiskFileItem Deserialization DoS");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"A cloud operations management application running on the remote web
server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) Manager running on
the remote web server is 6.x prior to 6.40. It is, therefore, affected
by a flaw in the Suite API CollectorHttpRelayController component due
to improper validation of DiskFileItem objects stored in the
'relay-request' XML before attempting deserialization. An
authenticated, remote attacker can exploit this issue, via a specially
crafted DiskFileItem object embedded in the XML, to move or write
arbitrary content to files, resulting in a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0020.html");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version 6.40 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_require_keys("installed_sw/vRealize Operations Manager");
  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http_func.inc");
include("install_func.inc");

app  = 'vRealize Operations Manager';
get_install_count(app_name:app, exit_if_zero:TRUE);
inst  = get_single_install(app_name:app, combined:TRUE);
port = inst['port'];
ver  = inst['version'];
path = inst['path'];

fix = '6.4';
ret = ver_compare(fix:fix,
                  minver: '6.0',
                  ver:ver,
                  strict:TRUE);

if (isnull(ret) || ret >= 0)
{
   audit(AUDIT_INST_VER_NOT_VULN, app, ver);
}
report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, severity:SECURITY_WARNING,
                   extra:report);
exit(0);

