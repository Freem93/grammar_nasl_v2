#TRUSTED 282ae5ce1b250cb5802ff4e4176a541238df41968531b85ccea1ef37faa923a453c205937059c289017866269117071daa2b4f39f853c7219bcf9fab44c02d889745a110df1e80bad548d04d935de6b81d9f322ce5e8fbc738e526166cd76485ce179125b2fd7a2785e2b0fd45faa75e802529850de6bd5dc16d82eafd8bb324466281ff54aaf6c1287f47cfde65c5d79f89e004b3443aeb526bf91b7c8b49b30e747ea9713fd35c9200bb90b5cebd2a0b752d5c97e406f33b00fdcfaecde4003b4f7ca2e0d1778af74ab1b3d520e9541208655f3c89ca13495d1d6a7ce6618754ea1abb3c74b8b59526851ea4402ff3f055496d65e69e57a12e590c213842086ad6b484f40dac625cef1df296551fe506815b6eca483a0bb9a9642b569269df546df4d8cecd326848476f81b28c079efb6b271a8c0ae32dc214cc2ed1e8f6151bb8689859f852895dbbd6e365f33e8d9a02ddf040bb6faa12c6bd82bd6f58d02ab51c91361929379d50cf5b7b28a173413d5443cb1b20b34db4b54b0c485691e91f7cdc4c86b371e3251e8b8668b91e1995bb439fb509ed803ce7430f91c53aedb04c6760847c76667e7ab4d2f42544476fbd56a0a555bb92f01f81345579698349a342db7390a7cce3d14563422faefbece46648d483b0a36426d73a2122c80e1a58afd6be87786fa44d63c68c13c2da5ab7132061903293c3db7de23bb92a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/05");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69517");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XR GNU C Library (glibc) Buffer Overflow (GHOST)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is potentially affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validated user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

Note that this issue only affects Cisco Network Convergence System
6000 Series routers.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69517");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf670adc");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69517.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

device_name = "Cisco Network Convergence System 6000 Series Router";

# Check model
model = get_kb_item("CISCO/model");
if(
  !isnull(model)
  &&
  tolower(model) !~ "ncs(6008|6k)"
) audit(AUDIT_HOST_NOT, device_name);

# First source failed, try another source
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6008" >!< model
    &&
    "NCS6k" >!< model
  ) audit(AUDIT_HOST_NOT, device_name);
}

# Check rough version
# 5.2.x / 5.4.x
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^5\.[24]\.")
  audit(AUDIT_HOST_NOT, device_name + " 5.2.x / 5.4.x");

# Affected :
# 5.2.4.BASE, i.e., 5.2.4
# 5.4.0.BASE, i.e., 5.4.0
if (
  version == "5.2.4"
  ||
  version == "5.4.0"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus69517' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, device_name, version);
