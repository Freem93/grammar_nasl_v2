#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88051);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id(
    "CVE-2015-5307",
    "CVE-2015-7183",
    "CVE-2015-8104"
  );
  script_bugtraq_id(
    77415,
    77524,
    77528
  );
  script_osvdb_id(
    129799,
    130089,
    130090
  );

  script_name(english:"Oracle VM VirtualBox < 4.0.36 / 4.1.44 / 4.2.36 / 4.3.34 / 5.0.10 Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 4.0.36, 4.1.44, 4.2.36, 4.3.34, or 5.0.10. It is,
therefore, affected by the following vulnerabilities :

  - A denial of service vulnerability exists due to an
    infinite loop condition in the KVM subsystem of the Linux
    kernel. A local attacker can exploit this, by triggering
    many Alignment Check (#AC) exceptions, to cause an OS
    panic or hang. (CVE-2015-5307)

  - A integer overflow condition exists in the
    PL_ARENA_ALLOCATE implementation in Netscape Portable
    Runtime (NSPR) due to a failure to properly validate
    user-supplied input during memory allocation. A remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service or execution of arbitrary code.
    (CVE-2015-7183)

  - A denial of service vulnerability exists due to an
    infinite loop condition in the KVM subsystem of the Linux
    kernel. A local attacker can exploit this, by triggering
    many Debug (#DB) exceptions, to cause an OS panic or hang.
    (CVE-2015-8104)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c48cc983");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 4.0.36 / 4.1.44 / 4.2.36 /
4.3.34 / 5.0.10 or later as referenced in the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev   = int(ver_fields[2]);

fix = '';

# Affected :
# 4.0.x < 4.0.36
# 4.1.x < 4.1.44
# 4.2.x < 4.2.36
# 4.3.x < 4.3.34
# 5.0.x < 5.0.10
if      (major == 4 && minor == 0 && rev < 36) fix = '4.0.36';
else if (major == 4 && minor == 1 && rev < 44) fix = '4.1.44';
else if (major == 4 && minor == 2 && rev < 36) fix = '4.2.36';
else if (major == 4 && minor == 3 && rev < 34) fix = '4.3.34';
else if (major == 5 && minor == 0 && rev < 10)  fix = '5.0.10';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
