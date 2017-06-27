#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93344);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2016-2207",
    "CVE-2016-2209",
    "CVE-2016-2210",
    "CVE-2016-2211",
    "CVE-2016-3644",
    "CVE-2016-3645",
    "CVE-2016-3646"
  );
  script_bugtraq_id(
    91431,
    91434,
    91435,
    91436,
    91437,
    91438,
    91439
  );
  script_osvdb_id(
    140636,
    140637,
    140638,
    140639,
    140640,
    140641,
    140642
  );

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF01 / 7.5.x < 7.5.3 HF03 / 7.8.x < 7.8.0 HF01 Multiple Vulnerabilities (SYM16-010)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine installed on the remote
host is 7.0.x prior to 7.0.5 HF01, 7.5.x prior to 7.5.3 HF03, or 7.8.x
prior to 7.8.0 HF01. It is, therefore, affected by multiple
vulnerabilities :

  - An array indexing error exists in the Unpack::ShortLZ()
    function within file unpack15.cpp due to improper
    validation of input when decompressing RAR files. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-2207)

  - A stack-based buffer overflow condition exists when
    handling PowerPoint files due to improper validation of
    user-supplied input while handling misaligned stream
    caches. An unauthenticated, remote attacker can exploit
    this, via a specially crafted PPT file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-2209)

  - A stack-based buffer overflow condition exists in the
    CSymLHA::get_header() function within file Dec2LHA.dll
    due to improper validation of user-supplied input when
    decompressing LZH and LHA archive files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted archive file, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-2210)

  - Multiple unspecified flaws exist in libmspack library
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, via
    a specially crafted CAB file, to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2211)

  - A heap buffer overflow condition exists in the
    CMIMEParser::UpdateHeader() function due to improper
    validation of user-supplied input when parsing MIME
    messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted MIME message, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-3644)

  - An integer overflow condition exists in the
    Attachment::setDataFromAttachment() function within file
    Dec2TNEF.dll due to improper validation of user-supplied
    input when decoding TNEF files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted TNEF file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-3645)

  - An array indexing error exists in the
    ALPkOldFormatDecompressor::UnShrink() function within
    the scan engine decomposer due to improper validation of
    input when decoding ZIP files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted ZIP file, to corrupt memory, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3646)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?175e28a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine version 7.0.5 HF01, 7.5.3 HF03,
7.8.0 HF01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_scan_engine_installed.nasl");
  script_require_keys("SMB/symantec_scan_engine/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app = 'Symantec Protection Engine';

function check_hf(path)
{
  local_var loc, locs, content;
  local_var line, matches, vuln;

  vuln = FALSE;

  hotfix_check_fversion_init();

  locs  = make_list(path, path + "Definitions\Decomposer\");

  foreach loc(locs)
  {
    if (hotfix_check_fversion(file:"dec2.dll", version:"5.4.6.2", path:loc))
    {
      vuln = TRUE;
      break;
    }
  }

  hotfix_check_fversion_end();

  return vuln;
}

port = kb_smb_transport();

path = get_kb_item_or_exit("Symantec/Symantec Protection Engine/Path");
version = get_kb_item_or_exit("Symantec/Symantec Protection Engine/Version");

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5 HF01";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5 HF01";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.3\." &&
    check_hf(path:path)
  ) fix = "7.5.3 HF03";

  if (version =~ "^7\.5\.[0-2]\.")
    fix = "7.5.3 HF03";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0 HF01";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
