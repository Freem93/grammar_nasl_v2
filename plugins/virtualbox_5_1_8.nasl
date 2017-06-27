#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94168);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/24 15:25:05 $");

  script_cve_id(
    "CVE-2016-5501",
    "CVE-2016-5538",
    "CVE-2016-5605",
    "CVE-2016-5608",
    "CVE-2016-5610",
    "CVE-2016-5611",
    "CVE-2016-5613",
    "CVE-2016-6304"
  );
  script_bugtraq_id(
    93150,
    93685,
    93687,
    93697,
    93711,
    93718,
    93728,
    93744
  );
  script_osvdb_id(
    144688,
    145968,
    145969,
    145970,
    145971,
    145972,
    145973,
    145974
  );

  script_name(english:"Oracle VM VirtualBox 5.0.x < 5.0.28 / 5.1.x < 5.1.8 Multiple Vulnerabilities (October 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Oracle VM VirtualBox application installed on the
remote host is 5.0.x prior to 5.0.28 or 5.1.x prior to 5.1.8. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple unspecified flaws exist in the Core
    subcomponent that allow a local attacker to gain
    elevated privileges. (CVE-2016-5501, CVE-2016-5538)

  - An unspecified flaw exists in the VirtualBox Remote
    Desktop Extension (VRDE) subcomponent that allows an
    unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-5605)

  - Multiple unspecified flaws exist in the Core
    subcomponent that allow a local attacker to cause a
    denial of service condition. (CVE-2016-5608,
    CVE-2016-5613)

  - An unspecified flaw exists in the Core subcomponent that
    allows a local attacker to impact on integrity and
    availability. (CVE-2016-5610)

  - An unspecified flaw exists in the Core subcomponent that
    allows a local attacker to disclose sensitive
    information. (CVE-2016-5611)

  - A flaw exists in the OpenSSL subcomponent, specifically
    within the ssl_parse_clienthello_tlsext() function in
    t1_lib.c due, to improper handling of overly large OCSP
    Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.28 / 5.1.8 or later as
referenced in the October 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

# Affected :
# 5.0.x < 5.0.28 / 5.1.x < 5.1.8
if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.26', strict:FALSE) < 0) fix = '5.0.26';
else if  (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.8', strict:FALSE) < 0) fix = '5.1.8';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
exit(0);
