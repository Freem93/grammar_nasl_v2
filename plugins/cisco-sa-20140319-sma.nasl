#TRUSTED b21a9e0be01394333085a0dcbcde4e40e8d16ff5e581daeddc27d3ca1794fa1935b3bcaa2f1398eef85bceff831752c19d680664b25dc1c91f490ec71d922c84c915229cb2864c8d08f0b78e006293d3ac2db1012c390910f7e201fa70020ef6ca00e10a1ac7ed8c246c83e15e7923ecf6ab6e46713b2d720ec1c6de5df75a5e06e4258aa42b73f2118b5e3e72420fdaade913ed67ec252ce17355030b9bb32e8356f33191bfab7d002a7e1178df6b987c640ce1edd7a7ecc891ea16d00bcec502ca7b4d1ce5f0d3d128c8dae531410b98acb302b4007ea1186914dac61cdbfe8c59f6e60f3fcf7420dad8a7cf15d0e6983bc48bc3bcd8982fda8ca8a82b7d36ecc87aa73642c084bea35991324075088630eab70ec8315b07f8ce879668fd19d2a115c537c9fbda06f3ddcdda1d3bed62801137f8d3c9636668608bbf75791073c2ac0926695da529f5d209d3536fae7a58f1ac6e21d8e5080877cf5441907ab365ce559a258d5ef9a8990cc3c8e3cad2f68901aa019178c6b148978beba016ecbc1df1bf13dd803586a82db1664896671417ae7f98275019aaf338be5bc9df269cd20d17ca5f25264deed5b598e43f153faa9177cfd894d8687e709a911c1b0590adf0eb30a2abe8c55d81eb59e01c244145c11abb7f5729b7c865336aca8015212fd29d5b48d6e91a69028c069645798749be068da84f0f55644b30304cd0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73211);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/17");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_osvdb_id(104660);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug80118");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Content Security Management Appliances Software Remote Code Execution (CSCug80118)");
  script_summary(english:"Checks SMA version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco Content
Security Management Appliance running on the remote host is affected
by a remote code execution vulnerability due to a flaw in Cisco
AsyncOS. An authenticated attacker could potentially exploit this
vulnerability to execute arbitrary code with the privileges of the
'root' user.

Note: In order to exploit this vulnerability, the FTP service and
Safelist/Blocklist (SLBL) service must be enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140319-asyncos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b22bd304");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140319-asyncos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");
  script_require_ports("Services/ftp", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[012]\.") # 7.2 and earlier
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.7\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.8\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.9\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^8\.0\.")
  display_fix = '8.1.1-013';
else if (ver =~ "^8\.1\.")
  display_fix = '8.1.1-013';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

# Compare version to determine if affected. FTP must also be enabled
# or paranoia setting must be above 1.
if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) == -1 &&
  (get_kb_list("Services/ftp") || report_paranoia > 1)
) vuln = TRUE;

# If local checks are enabled, confirm whether SLBL service is
# enabled. If they are not, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/slblconfig", "slblconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Blocklist: Enabled", string:buf))
    vuln = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    if (!local_checks) report +=
      '\n' + 'Nessus was unable to determine whether the End-User Safelist /' +
      '\n' + 'Blocklist service is running because local checks are not' +
      '\n' + 'enabled.' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);
