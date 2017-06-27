#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89112);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2007-2953",
    "CVE-2008-2712",
    "CVE-2008-3432",
    "CVE-2008-4101",
    "CVE-2008-5077",
    "CVE-2009-0025"
  );
  script_bugtraq_id(
    25095,
    29715,
    30648,
    30795,
    33150,
    33151
  );
  script_osvdb_id(
    38674,
    46306,
    48971,
    51164,
    51368,
    51435,
    51436,
    51437
  );
  script_xref(name:"VMSA", value:"2009-0004");

  script_name(english:"VMware ESX Multiple Vulnerabilities (VMSA-2009-0004) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, is affected by multiple vulnerabilities :

  - A format string flaw exists in the Vim help tag
    processor in the helptags_one() function that allows a
    remote attacker to execute arbitrary code by tricking a
    user into executing the 'helptags' command on malicious
    help files. (CVE-2007-2953)

  - Multiple flaws exist in the Vim system functions due to
    a failure to sanitize user-supplied input. An attacker
    can exploit these to execute arbitrary code by tricking
    a user into opening a crafted file. (CVE-2008-2712)

  - A heap-based buffer overflow condition exists in the Vim
    mch_expand_wildcards() function. An attacker can exploit
    this, via shell metacharacters in a crafted file name,
    to execute arbitrary code. (CVE-2008-3432)

  - Multiple flaws exist in Vim keyword and tag handling due
    to improper handling of escape characters. An attacker
    can exploit this, via a crafted document, to execute
    arbitrary shell commands or Ex commands. (CVE-2008-4101)

  - A security bypass vulnerability exists in OpenSSL due to
    a failure to properly check the return value from the
    EVP_VerifyFinal() function. A remote attacker can
    exploit this, via a malformed SSL/TLS signature for DSA
    and ECDSA keys, to bypass the validation of the
    certificate chain. (CVE-2008-5077)

  - A security bypass vulnerability exists in BIND due to a
    failure to properly check the return value from the
    OpenSSL DSA_verify() function. A remote attacker can
    exploit this, via a malformed SSL/TLS signature, to
    bypass the validation of the certificate chain on those
    systems using DNSSEC. (CVE-2009-0025)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0004");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

fixes = make_array();
fixes["ESX 3.5"]  = 158874;
fixes["ESX 4.0"]  = 219382;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment

  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
