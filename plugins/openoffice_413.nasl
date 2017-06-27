#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94199);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id(
    "CVE-2016-1513",
    "CVE-2016-6803",
    "CVE-2016-6804"
  );
  script_bugtraq_id(
    92079,
    93774
  );
  script_osvdb_id(
    141963,
    145721,
    145722
  );
  script_xref(name:"IAVB", value:"2016-B-0152");

  script_name(english:"Apache OpenOffice < 4.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.3. It is, therefore, affected by the following
vulnerabilities :

  - A memory corruption issue exists in the Impress tool due
    to improper validation of user-supplied input when
    handling elements in invalid presentations. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted MetaActions in an ODP or OTP file, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-1513)

  - A privilege escalation vulnerability exists due to the
    use of an unquoted Windows search path. A local attacker
    can exploit this to execute arbitrary code with elevated
    privileges. (CVE-2016-6803)

  - A privilege escalation vulnerability exists due to the
    use of a fixed path to load system binaries. A local
    attacker can exploit this, via a specially crafted DLL
    file in the library path, to inject and execute
    arbitrary code with elevated privileges. (CVE-2016-6804)");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2016-1513.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2016-6803.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2016-6804.html");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/openoffice/4.1.2-patch1/hotfix.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.3 or later. Alternatively,
the vendor has released a hotfix for 4.1.2 that resolves
CVE-2016-1513. Note that the hotfix only resolves this one
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

app_name   = "OpenOffice";

get_kb_item_or_exit("SMB/Registry/Enumerated");

install    = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
build      = install['version'];
path       = install['path'];
version_ui = install['display_version'];

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FAIL, app_name);

buildid = int(matches[2]);

flag   = FALSE;
caveat = '';

# Version 4.1.2 is build 9782
if (buildid == 9782)
{
  # A hotfix was made available for version 4.1.2 called "Patch 1" that
  # updates tl.dll. The version of tl.dll does not change, so we check
  # the timestamp.
  fixed_ts  = 1467765120;
  file_path = hotfix_append_path(path:path, value:"\program\tl.dll");
  file_ts   = hotfix_get_timestamp(path:file_path);

  # If we were able to get a timestamp, determine vulnerability
  if (file_ts['error'] == HCF_OK)
  {
    file_ts = file_ts['value'];
    if (file_ts < fixed_ts)
      flag = TRUE;
    else
      audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui + " (Patch 1)", path);
  }

  # If we weren't able to get a timestamp but report paranoia is Paranoid,
  # report the vuln with a caveat; otherwise, audit out.
  else if (report_paranoia > 1)
  {
    flag = TRUE;
    caveat = '  \nNote that Nessus was unable to determine if a hotfix has been applied.\n';
  }
  else
    audit(AUDIT_PARANOID);
}

# Version 4.1.3 is build 9783
else if (buildid < 9783)
  flag = TRUE;

if (!flag)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : 4.1.3 (413m1 / build 9783)' +
  '\n' + caveat;
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
