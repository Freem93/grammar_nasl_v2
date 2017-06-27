#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73595);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/07 13:14:39 $");

  script_cve_id("CVE-2014-1209", "CVE-2014-1210");
  script_bugtraq_id(66772, 66773);
  script_osvdb_id(105726, 105727);
  script_xref(name:"VMSA", value:"2014-0003");

  script_name(english:"VMware vSphere Client Multiple Vulnerabilities (VMSA-2014-0003)");
  script_summary(english:"Checks the version of vSphere Client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization client application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of vSphere Client installed on the remote Windows host is
affected by the following vulnerabilities :

  - An error exists related to the vSphere Client that
    could allow an updated vSphere Client to be downloaded
    from an untrusted source. (CVE-2014-1209)

  - An error exists related to the vSphere Client and
    server certificate validation that could allow an
    attacker to spoof a vCenter server. Note that this
    issue only affects vSphere Client versions 5.0 and 5.1.
    (CVE-2014-1210)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0003.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vSphere Client 5.0 Update 3 / 5.1 Update 2 or later.

In the case of vSphere Client 4.x, refer to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("vsphere_client_installed.nasl");
  script_require_keys("SMB/VMware vSphere Client/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/VMware vSphere Client/*/Path");

info = '';
info2 = '';
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
  if (ver =~ '^4\\.1\\.0$' && int(build) < 1651023)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.1.0 build 1651023\n';
  }
  else if (ver =~ '^4\\.0\\.0$' && int(build) < 1651021)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.0 build 1651021\n';
  }
  else if (ver =~ '^5\\.1\\.0$' && int(build) < 1471691)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.1.0 build 1471691\n';
  }
  else if (ver =~ '^5\\.0\\.0$' && int(build) < 1300600)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.0 build 1300600\n';
  }
  else info2 += ' and ' + version;
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since VMware vSphere Client '+info2+' '+be+' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
