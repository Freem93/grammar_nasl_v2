#TRUSTED ad8d7a3f42cedb45c20bfd6d5e549e35a24b65286bb234a2522e85856f25dd69bfde5499b730c2adfa4e5c9109e09cb710d00b50c8d6419807281c174565eb23bef1444ae8f60b821566b99b1a5eae7e94a5a34b5019372f9d8e9145cece9926457d2145ea71a0ccc1e7f15e914ba35f684b5a7eb2eedb8b6b62830f43fd4fafef5ff986dac59e3eb26fdc29c2d00f5072a7b5e3f73db626ad0bfe38f33fda0a908cce5a2a004994fef6590358bc9627c671d19e08236a0de65f5c833de5531f7484e8c6f05d7ce7fd148c270960cc641ba23c47f5a05285351ed3d32b45d224cb254dbc82dd62135bd4d6dc163c82bbc1238813cac77ab27d495d47df5f8d566b86a12860d59642caf2d210c67f81f3cb3edbcedf89c77227e16bfe00c5352b7f55a51c8976d132e69aa37ac6cfab1a615968982556a8407c9fb800361c5825f7bc7dafc97efb22a1c7da8d4d04cc0314d62d932b8ec5c01fd884ceb8a3b8aab0bc6006bda9c0c7d2f5ef2316fac72e4e8eee3c83702c42fb3950fa41b616d7be9927cc45a453e6aa9334db55e9e186e0dac92d0a964af59767ce91019c64556114ccb5f7ab119118fa1c9e640e106f1a7378486b75d250f73f2a4eaf6f0df28038d07ce5629b82b5111d63cb26d16ef2c8db4689a958d565dead1a9c06f605cfd45b714d0021ac90df4bf8a6db75b38e057c7d9dd70af70b8463752b44684e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81913);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296"
  );
  script_bugtraq_id(71757, 71758, 71761, 71762);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);
  script_xref(name:"CERT", value:"852879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus27229");

  script_name(english:"Cisco IOS XR NCS 6000 Multiple ntpd Vulnerabilities");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of IOS XR software that
is affected by the following vulnerabilities :

  - Errors exist related to weak cryptographic pseudorandom
    number generation (PRNG), the functions 'ntp_random' and
    and 'config_auth', and the 'ntp-keygen' utility. A
    man-in-the-middle attacker can exploit these to disclose
    sensitive information. (CVE-2014-9293, CVE-2014-9294)

  - Multiple stack-based buffer overflow errors exist in the
    Network Time Protocol daemon (ntpd), which a remote
    attacker can exploit to execute arbitrary code or cause
    a denial of service by using a specially crafted packet.
    (CVE-2014-9295)

  - An error exists in the 'receive' function in the Network
    Time Protocol daemon (ntpd) that allows denial of
    service attacks. (CVE-2014-9296)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141222-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79cfbf7f");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534319");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco bug ID
CSCus27229.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
override = FALSE;

# Check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "^cisco([Nn]cs|NCS)(6008|6k)")
    audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
  ) audit(AUDIT_HOST_NOT, "an affected model");
}

# Check version
# per bug page :
#  - "5.2.4.BASE" in "Known Affected" list
if (version != "5.2.4") audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_staus", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
      if (
        "%NTP is not enabled." >< buf
        &&
        "system poll" >!< buf
        &&
        "Clock is" >!< buf
      ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled.");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCus27229' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
