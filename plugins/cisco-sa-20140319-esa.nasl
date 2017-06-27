#TRUSTED a08d20d5a396f67463863ab236df0a2ff5e7f6a465543423f13b2df08a166ec09dcfd0acde49ac0504f0be2904aa097357900e1a32489274d33c5b6b954b1186d9cec53d54283d0be8292dbf2d4f9fa593f1cafb614ee77b7245b09f808ba1188ea5d7d31d54d7cdf8c4133218dc12f60bf8f98df86b0e740bda797d55a67976c3820a75487b07e0cd0a9a043680c46c768ab15299211f2738bdd35a2f55a986d31a66e251dc8000f983cb462514396d343a5bec5bcb75ad65852e68b740b1ce17c3445ed9add16b41adde513c8be86b49b67dc44c6c72be4c11aaa6e9d6019125409266466556bbb766f2a3d8c6b4edd33f1502433aafd4ae28cf79c8e317ba36f9cfbfd982b972f660be67e92abb47492eea8d9ac1f05226dfa731bc7ce8115645651a594f7d210f40f14a5dc426e1bab77ce3030a8654c5fd37d3183cf7129db05796f9c59dd2b980475b7112953ecaab09204d3128aad0c54a5590fcd5eb787b3a2af4905daff9e6d822e0b532b1a7d183064d756f1dca70f309f4f6aa53433f8fef9c83182910d26f2f4e4f1f68128aaf7598948981389688f4bce170a4f6842e75190231f9116355a1ce09cbfc4f581c87fd7560ae05cf24031a4ffcfae4941399b4a732847e03690692e65c2771a99ac725ef781a8a737722295ceb92f9f9499b628d2ce037c285237afe5bc0fb89ec3460b898c592d797a4863a6f2b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73210);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/17");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_osvdb_id(104660);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug79377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Email Security Appliances Software Remote Code Execution (CSCug79377)");
  script_summary(english:"Checks ESA version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco Email
Security Appliance running on the remote host is affected by a remote
code execution vulnerability due to a flaw in Cisco AsyncOS. An
authenticated attacker could potentially exploit this vulnerability to
execute arbitrary code with the privileges of the 'root' user.

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
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Services/ftp", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[01]\.") # 7.1 and prior
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.3\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^7\.5\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.6\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.8\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.1-023';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

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
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);


