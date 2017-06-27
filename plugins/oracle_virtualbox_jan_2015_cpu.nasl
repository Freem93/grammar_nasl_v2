#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
  script_id(80915);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:53:02 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470",
    "CVE-2014-6588",
    "CVE-2014-6589",
    "CVE-2014-6590",
    "CVE-2014-6595",
    "CVE-2015-0377",
    "CVE-2015-0418",
    "CVE-2015-0427"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    72194,
    72196,
    72202,
    72206,
    72213,
    72216,
    72219
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732,
    117338,
    117339,
    117340,
    117341,
    117342,
    117343,
    117344
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Oracle VM VirtualBox < 3.2.26 / 4.0.28 / 4.1.36 / 4.2.28 / 4.3.20 Multiple Vulnerabilities (January 2015 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Oracle VM VirtualBox that is
prior to 3.2.26 / 4.0.28 / 4.1.36 / 4.2.28 / 4.3.20. It is, therefore,
affected by multiple vulnerabilities in the following subcomponents :
  
  - Core
  - OpenSSL
  - VMSVGA device");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade Oracle VM VirtualBox to 3.2.26 / 4.0.28 / 4.1.36 / 4.2.28 /
4.3.20 or later as referenced in the January 2015 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Oracle VM VirtualBox';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

fix = '';

# Affected :
# 3.2.x < 3.2.26
# 4.0.x < 4.0.28
# 4.1.x < 4.1.36
# 4.2.x < 4.2.28
# 4.3.x < 4.3.20
if (major == 3 && minor == 2 && rev < 26) fix = '3.2.26';
else if (major == 4 && minor == 0 && rev < 28) fix = '4.0.28';
else if (major == 4 && minor == 1 && rev < 36) fix = '4.1.36';
else if (major == 4 && minor == 2 && rev < 28) fix = '4.2.28';
else if (major == 4 && minor == 3 && rev < 20) fix = '4.3.20';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

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

