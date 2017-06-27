#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90796);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/20 15:01:13 $");

  script_cve_id(
    "CVE-2015-2808",
    "CVE-2016-2004",
    "CVE-2016-2005",
    "CVE-2016-2006",
    "CVE-2016-2007",
    "CVE-2016-2008"
  );
  script_bugtraq_id(
    73684,
    87037,
    87040,
    87053,
    87055,
    87061
  );
  script_osvdb_id(
    117855,
    137412,
    137413,
    137414,
    137415,
    137416
  );
  script_xref(name:"CERT", value:"267328");
  script_xref(name:"EDB-ID", value:"39858");
  script_xref(name:"IAVA", value:"2016-A-0110");
  script_xref(name:"HP",value:"emr_na-c05085988");
  script_xref(name:"HP",value:"HPSBGN03580");
  script_xref(name:"HP",value:"SSRT102163");
  script_xref(name:"HP",value:"PSRT102293");
  script_xref(name:"HP",value:"PSRT102979");
  script_xref(name:"HP",value:"PSRT102980");
  script_xref(name:"HP",value:"PSRT102981");
  script_xref(name:"HP",value:"PSRT102956");
  script_xref(name:"HP",value:"PSRT102948");
  script_xref(name:"ZDI", value:"ZDI-16-245");
  script_xref(name:"ZDI", value:"ZDI-16-246");
  script_xref(name:"ZDI", value:"ZDI-16-247");

  script_name(english:"HP Data Protector 7.0x < 7.03 build 108 / 8.1x < 8.15 / 9.0x < 9.06 Multiple Vulnerabilities (HPSBGN03580) (Bar Mitzvah)");
  script_summary(english:"Checks versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Data Protector installed on the remote host is 7.0x
prior to 7.03 build 108, 8.1x prior to 8.15, or 9.0x prior to 9.06. It
is, therefore, affected by the following vulnerabilities :

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A flaw exists due to a failure to authenticate users,
    even with Encrypted Control Communications enabled. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-2004)

  - Multiple overflow conditions exist due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these issues, via specially
    crafted 'User Name' or 'Domain' field in an EXEC_BAR
    request, to cause a stack-based buffer overflow,
    resulting in a denial of service or the execution of
    arbitrary code. (CVE-2016-2005, CVE-2016-2006)

  - An overflow condition exists due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this, via specially crafted
    EXEC_SCRIPT request, to cause a stack-based buffer
    overflow, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2016-2007)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to disclose sensitive
    information or execute arbitrary code. (CVE-2016-2008)");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c05085988
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b20bcde7");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-247/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Data Protector 7.03 build 108 (7.03_108) / 8.15 / 9.06
or later per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Encrypted Communication Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/hp_openview_dataprotector", 5555);
  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl", "hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");

  exit(0);
}

include("hp_data_protector_version.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

# patterns matching affected platforms
hpux_pat = "^11\.(11|23|31)$";
solaris_pat = "^5(\.|$|[^0-9])";
windows_pat = "^(5\.2|6\.\d+)$";
linux_pat = "(el[4-7]|SLES(9|10|11))(\.|$|[^0-9])";

# patterns for matching against affected versions
ver_700_pat = "^A\.07\.0[0-3]$";
ver_800_pat = "^A\.08\.1[0-4]$";
ver_900_pat = "^A\.09\.0[0-5]$";

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 108,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 108,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: 108,
                        severity: SECURITY_HOLE,
                        port:port);

## 8.1x

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 211,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 211,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 211,
                        severity: SECURITY_HOLE,
                        port:port);

## 9.0x

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 107,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 107,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 107,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check_exit(port:port);
