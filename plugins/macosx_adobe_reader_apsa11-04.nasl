#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57044);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2011-2445",
    "CVE-2011-2450",
    "CVE-2011-2451",
    "CVE-2011-2452",
    "CVE-2011-2453",
    "CVE-2011-2454",
    "CVE-2011-2455",
    "CVE-2011-2456",
    "CVE-2011-2457",
    "CVE-2011-2458",
    "CVE-2011-2459",
    "CVE-2011-2460",
    "CVE-2011-2462",
    "CVE-2011-4369",
    "CVE-2011-4370",
    "CVE-2011-4371",
    "CVE-2011-4372",
    "CVE-2011-4373"
  );
  script_bugtraq_id(
    50618,
    50619,
    50620,
    50621,
    50622,
    50623,
    50624,
    50625,
    50626,
    50627,
    50628,
    50629,
    50922,
    51092,
    51348,
    51349,
    51350,
    51351
  );
  script_osvdb_id(
    77018,
    77019,
    77020,
    77021,
    77022,
    77023,
    77024,
    77025,
    77026,
    77027,
    77028,
    77029,
    77529,
    78026,
    78245,
    78246,
    78247,
    78248
  );

  script_xref(name:"EDB-ID",value:"18366");

  script_name(english:"Adobe Reader <= 10.1.1 / 9.4.6 U3D Memory Corruption (APSA11-04, APSB11-28, APSB11-30, APSB12-01) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected
by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior or equal to 10.1.1 or 9.4.6. It is, therefore, affected by a
memory corruption issue related to the Universal 3D (U3D) file format.
A remote attacker can exploit this, by convincing a user to view a
maliciously crafted PDF file, to cause an application crash or to
execute arbitrary code.

Note that the Adobe Reader X user-specific option to use 'Protected 
Mode' prevents an exploit of this kind from being executed, but Nessus
cannot test for this configuration option.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-28.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-30.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 9.5 / 10.1.2 or later. If the product
is Adobe Reader X, and upgrading is not an option, then the
user-specific option 'Protected Mode' should be enabled.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader U3D Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (!get_kb_item("Host/MacOSX/Version"))
  audit(AUDIT_OS_NOT, "Mac OS X");

app = "Adobe Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

# Affected 9.x <= 9.4.6 / 10.x <= 10.1.1
ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 9 && ver[1] < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] <= 6)
)
  fix = "9.5";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] <= 1)
)
  fix = "10.1.2";
else
  fix = "";

if (fix)
{
  info =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:info, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
