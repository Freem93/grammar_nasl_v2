#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95657);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/12 14:59:32 $");

  script_cve_id("CVE-2016-7458");
  script_bugtraq_id(94483);
  script_osvdb_id(147773);
  script_xref(name:"VMSA", value:"2016-0022");
  script_xref(name:"IAVB", value:"2016-B-0182");
  script_xref(name:"IAVB", value:"2016-B-0183");

  script_name(english:"VMware vSphere Client XXE Injection Information Disclosure (VMSA-2016-0022)");
  script_summary(english:"Checks the version of vSphere Client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization client application installed that
is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of vSphere Client installed on the remote Windows host is
affected by an information disclosure vulnerability due to an
incorrectly configured XML parser accepting XML external entities
(XXE) from an untrusted source. An unauthenticated, remote attacker
can exploit this issue to disclose arbitrary files by convincing a
user to connect to a malicious instance of a vCenter Server or ESXi
host containing specially crafted XML data.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vSphere Client version 5.5 Update 3e / 6.0 Update 2a or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vsphere_client_installed.nasl");
  script_require_keys("SMB/VMware vSphere Client/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/VMware vSphere Client/*/Path");

info = '';
unaffected = make_list();
vuln = 0;

foreach version (keys(installs))
{
  path = installs[version];
  version = version - 'SMB/VMware vSphere Client/' - '/Path';
  matches = eregmatch(pattern:'^([0-9\\.]+) build ([0-9]+)$', string:version);
  if (matches)
  {
    ver = matches[1];
    build = matches[2];
  }
  if (ver =~ '^5\\.5\\.0$' && int(build) < 4032365)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.0 build 4032365\n';
  }
  else if (ver =~ '^6\\.0\\.0$' && int(build) < 4437566)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0.0 build 4437566\n';
  }
  else
    unaffected = make_list(unaffected, version);
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:info
  );
  exit(0);
}

if (max_index(unaffected) > 0)  audit(AUDIT_INST_VER_NOT_VULN, "VMware vSphere Client", unaffected);
else exit(1, 'Unexpected error - \'unaffected\' is empty.');
