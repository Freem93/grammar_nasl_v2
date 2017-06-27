#TRUSTED 69f847f36c8799e59f99ef3834743124ee9f615c382f54f6e259fe57776c2a1a57307eaa218e559a52a1038cb400ce74d736ce7bb53f84efc297ff5910282a0712a958d2c48c193e91935d75ba3143b4579cb0d4a23955edf6068b5a8c1cac708b84293fa309327d849b741e4fdb309dec8d7f95b1386dbf2c0e0c58c92553bc2384b0a49f39c3089f647431b9837aafe13e9e89dd9653f207b7984a2f78203dc2ede42c1efb99168aa6d3a0dbe5432458e767b64d67a996449ff54f8a115132422ea3bae5771776d6f2f588bb0a76971cc7814b810fe7b6ba18118835503674878d6e90b1d261d61bdcf851a86c1f12de5aded9bea509150dac0219622d2c86b94bbc1697c437caec2e1f281aacb3748a1008534ec7999d638d67570fb5fa38ebee1827d8662fb95adac0a37fb0e023266d91d476a380cf3a466305782ad83035d3ef65723b69fd0d5f79534b8792334b330f6d87afd6c553302f8552baf80a491ecfbc6b17eb23a82b432a9db903440fa08ead06dafce3416ecdcd44123784d8b6db707dfd99d8ac2b61989720a33017db2a08b2cb61dd33e23c334b1ac5e3f952a6a925e15cd8b345c0ea540b5e05914d0c638a0e50294d6540264387a3759abf4a655e8ffde7e8ecc20741824ab1933d58073d0bb6c2019da9e3f21bd40c24f6eb3acbe285ee25e50ca22031785e95d024fd01539f4ce045b9f93767af28
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81594);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/05");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69732");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU C Library (glibc) Buffer Overflow (CSCus69732) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a heap-based buffer overflow vulnerability in the
GNU C Library (glibc) due to improperly validated user-supplied input
to the __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2() functions. This allows a remote attacker to cause a
buffer overflow, resulting in a denial of service condition or the
execution of arbitrary code.

Note that only the following devices are listed as affected :

  - Cisco ASR 1000 Series Aggregation Services Routers
  - Cisco ASR 920 Series Aggregation Services Routers
  - Cisco ASR 900 Series Aggregation Services Routers
  - Cisco 4400 Series Integrated Services Routers
  - Cisco 4300 Series Integrated Services Routers
  - Cisco Cloud Services Router 1000V Series");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69732");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69732.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Model check
# Per Bug CSCus69732
if (
  !(
    "ASR1k"    >< model ||
    "ASR920"   >< model ||
    "ASR900"   >< model ||
    "ISR4400"  >< model ||
    "ISR4300"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Version check
# Per Bug CSCus69732
# - top list (raw)
# - and bottom list (converted)
if (
  version == "3.10.0S" || #bl
  version == "3.10.4S" || #bl
  version == "3.11.0S" || #bl
  version == "3.11.2S" || #bl
  version == "3.11.3S" ||
  version == "3.12.0S" || #bl
  version == "3.12.1S" || #bl
  version == "3.13.0S" || #bl
  version == "3.13.2S" ||
  version == "3.14.S"  ||
  version == "3.4.7S"  ||
  version == "3.7.0S"  || #bl
  version == "3.7.6S"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69732' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
