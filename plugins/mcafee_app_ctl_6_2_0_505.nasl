#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87922);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2016-1715");
  script_osvdb_id(132576);
  script_xref(name:"MCAFEE-SB", value:"SB10145");
  script_xref(name:"IAVB", value:"2016-B-0011");
  script_xref(name:"ZDI", value:"ZDI-16-007");

  script_name(english:"McAfee Application Control swin.sys Memory Corruption (SB10145)");
  script_summary(english:"Checks the version of McAfee Application Control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a security application installed that is affected
by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Application Control is 6.1.0 prior to build 706,
6.1.1 prior to build 404, 6.1.2 prior to build 449, 6.1.3 prior to
build 441, or 6.2.0 prior to build 505. It is, therefore, affected by
a kernel memory corruption issue in the swin.sys driver when handling
a 786 syscall, which causes a zero to be written to an arbitrary
location in kernel memory. A local attacker can exploit this, via a
crafted web page or file, to cause a denial of service, gain elevated
privileges, or possibly execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10145");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Application Control version 6.1.0.706 / 6.1.1.404 /
6.1.2.449 / 6.1.3.441 / 6.2.0.505 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:application_control");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_app_ctl_installed.nbin");
  script_require_keys("installed_sw/McAfee Application Control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'McAfee Application Control';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (get_kb_item("SMB/ARCH") != "x86")
  audit(AUDIT_ARCH_NOT, "x86");

install = get_single_install(
  app_name : app,
  exit_if_unknown_ver : TRUE
);

path = install['path'];
version = install['version'];

fix = NULL;

if (version =~ "^6\.1\.0" && (ver_compare(ver:version, fix:"6.1.0.706") < 0))
  fix = "6.1.0.706";
else if (version =~ "^6\.1\.1" && (ver_compare(ver:version, fix:"6.1.1.404") < 0))
  fix = "6.1.1.404";
else if (version =~ "^6\.1\.2" && (ver_compare(ver:version, fix:"6.1.2.449") < 0))
  fix = "6.1.2.449";
else if (version =~ "^6\.1\.3" && (ver_compare(ver:version, fix:"6.1.3.441") < 0))
  fix = "6.1.3.441";
else if (version =~ "^6\.2\.0" && (ver_compare(ver:version, fix:"6.2.0.505") < 0))
  fix = "6.2.0.505";

port = get_kb_item("SMB/transport");
if (! port)
  port = 445;

if (fix)
{
    if (report_verbosity > 0)
  {
    report =
      '\n  Installed path    : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, app, version);
