#TRUSTED 38af47878ef853ff91d3ee12ba936b251d325f3e0ff398431f65bf862d2999cf63431494002138cd28f24346e3036a4a287bb40aa10eed9c81b9ae6ad01cf63821d01b1ba21169da905e0a18a9e7a62ac9805b2e88f16965744ae08f8a1361f912ca65266478932ff7038c0ac610fb26c45fdeed83ec5fa5c00d2cea268fffc7a8a5068cf138cc9ec0020855180bb24d02523ee08e024ac0ce4f1dd4e09aa216839135df83a3767c3eaf394038ce7f2e9bc1b514e1b8a49b7c5daf86d4a65ae207b07751275782a3a01be18764f9c83e6b0e6b69ed541ce409a50c86b5918004a0c41f2ff986e0cfa712601bf67f8a7ebd53e63de811ca18a6574527ecfd51f80db8ef3551129529f5eb33e73524770cfa438e8acd63369edeb600ad8eafd659561061a176e4ed0f572d69aa578ea1c8014326538ed5f172a04c0c1afee8d031edd97018fa6ddd75f9f86fcb7fd0bfaf56d99175cd729d7e38ecf155c26d12f14ffa608ff9a73ac4e66a9ef48aee3a1b66cc459b4390b8871fa58af11489269498796604d36dee53d43a015666edd6998438eecc00fa7526934effa7867b0a17e1998a15c60d284710d9c064d1aedb554177e19af2673b9a0dd2962e944264ac466bdc01d515e1bf4e7dec4b71627c8f03d1f5d3833eec8340b14b37dc0690e4d0171edb015367f955836194c4b80c6b42d2b9a6044eead0c20cfa119e1f5161
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81595);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/05");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69731");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU GNU C Library (glibc) Buffer Overflow (CSCus69731) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is potentially affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validated user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

Note that this issue only affects those IOS XE instances that are
running as a 'Nova' device, and thus, if the remote IOS XE instance
is not running as a 'Nova' device, consider this a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69731");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69731.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Bug notes these are affected on 'Nova' devices
# only.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Per Bug CSCus69731 (converted from IOS vers)
# No model restrictions listed
# Further note that IOS version '15.0(2)EX'
# is not mapped and thus, omitted.
if (
  version == "3.1.0SG" ||
  version == "3.2.0SE" ||
  version == "3.2.0SG" ||
  version == "3.2.0XO" ||
  version == "3.3.0SE" ||
  version == "3.3.0XO" ||
  version == "3.4.0SG" ||
  version == "3.5.0E"  ||
  version == "3.6.0E"  ||
  version == "3.7.0E"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69731' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
