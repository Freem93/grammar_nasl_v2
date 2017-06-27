#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79147);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3510",
    "CVE-2014-6271",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-6277",
    "CVE-2014-6278"
  );
  script_bugtraq_id(
    69076,
    69078,
    69081,
    69082,
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_osvdb_id(
    109891,
    109892,
    109893,
    109895,
    112004,
    112096,
    112097,
    112158,
    112169
  );
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"VMSA", value:"2014-0010");

  script_name(english:"VMware vCenter Converter 5.1.x < 5.1.2 / 5.5.x < 5.5.3 Multiple Vulnerabilities (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of VMware vCenter Converter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Converter installed on the remote
Windows host is 5.1.x prior to 5.1.2 or 5.5.x prior to 5.5.3. It is,
therefore, affected by the following vulnerabilities :

  - A command injection vulnerability exists in GNU Bash
    known as Shellshock, which is due to the processing of
    trailing strings after function definitions in the
    values of environment variables. This allows a remote
    attacker to execute arbitrary code via environment
    variable manipulation depending on the configuration of
    the system. While this host is not directly impacted by
    Shellshock, the standalone Converter application does
    deploy a Helper VM during Linux P2V conversions. This
    Helper VM contains a vulnerable version of Bash.
    (CVE-2014-6271, CVE-2014-6277, CVE-2014-6278,
    CVE-2014-7169, CVE-2014-7186, CVE-2014-7187)

  - A memory double-free error exists in 'd1_both.c' related
    to handling DTLS packets that allows denial of service
    attacks. (CVE-2014-3505)

  - An unspecified error exists in 'd1_both.c' related to
    handling DTLS handshake messages that allows denial of
    service attacks due to large amounts of memory being
    consumed. (CVE-2014-3506)

  - A memory leak error exists in 'd1_both.c' related to
    handling specially crafted DTLS packets that allows
    denial of service attacks. (CVE-2014-3507)

  - A NULL pointer dereference error exists related to
    handling anonymous ECDH cipher suites and crafted
    handshake messages that allows denial of service attacks
    against clients. (CVE-2014-3510)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0010.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Converter 5.1.2 / 5.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_converter");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_converter_installed.nbin");
  script_require_keys("installed_sw/VMware vCenter Converter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "VMware vCenter Converter";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
build   = install['Build'];
path    = install['path'];

if (version =~ "^5\.1($|\.)")
{
  fix = '5.1.2';
  fix_disp = '5.1.2 Build 2183568';
}
else if (version =~ "5\.5($|\.)")
{
  fix = '5.5.3';
  fix_disp = '5.5.3 Build 2183569';
}
else fix = NULL;

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{

  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
