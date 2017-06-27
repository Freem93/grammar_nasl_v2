#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92038);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id("CVE-2016-4810");
  script_bugtraq_id(90956);
  script_osvdb_id(139259);
  script_xref(name:"IAVB", value:"2016-B-0098");

  script_name(english:"Citrix Studio < 7.6.1000 Insecure Access Policy Configuration (CTX213045)");
  script_summary(english:"Checks the version of Citrix Studio.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Studio, bundled with Citrix XenApp or
XenDesktop, is prior to 7.6.1000. It is, therefore, affected by an
unspecified security bypass vulnerability. An unauthenticated, remote
attacker can exploit this to set Access Policy rules on the XenDesktop
Delivery Controller, resulting in an insecure Access Policy
configuration.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX213045");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory for update information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenapp");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xendesktop");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_studio_installed.nbin");
  script_require_keys("installed_sw/Citrix Studio");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Citrix Studio";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
disp_ver = install['display_version'];
path = install['path'];

if (version =~ "^7\." && ver_compare(ver:version, fix:'7.6.0.1000') < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report =
    '\n  Installed version : ' + disp_ver +
    '\n  Fixed version     : See vendor advisory.\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
