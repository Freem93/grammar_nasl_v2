#TRUSTED 73662d40002a0cba26123fbf3cdf0747bf6ba44e7c23d0f359acc4b0ccf5caa641a21236b9962a712480d7d00f5baad5e7ab1e5f95a598b55c16b7e38cb3a74071a17d9a899fb44fd7829c7f6ffd8a6c7f374fd3dab80c7f0442d6f16681a51634cf4e6f945a842cb8004e1d8ff9b06f2d55a65b92898b4f6d4e0adcfa5b2a2f58f24c0a00bf7fdacb541b01ba56c474381879602fb0930790718005ce3fc5f055eb9d6c47be492b1fdbbc136b6c78a78e12f693d2d2a0a0df138484e55fd027b1f0e3ef2ca4588983c925b742d3727bcdbdf5201684f046d086e5a46d137820691bf5e3e011627def105a8d36986a575748a79b88f0810a17f1fff9ee930a78f87993e3b9a93540a5ab757673514f8983fe325e0b596f78e3b26e46105adbbba3e3f3482fc7bfefe2f0ee762b812c373fb2e9e21da7e2434891d3476bf8ddf816648f5c861f7a5625c382eac596c4f6a2ddcbe0564ab2a47ea3496f87e282246e213b14d5542e5b1777b34c32ed4ffdcbc6fd7ce28e3187059f6d8b9dbbb99142011b9ce7f14adcc917a83ad43a6c35fec97a8650255c7881a89fb5a8f286e52368a99b2b16ecd9fb13ed7cd2bd70e5f444d5a49d0defe5f10ee7e449e191b279bf8035eebac9c3efcf55e2adfb74cf6113378833bffac15f00c46920c190f4fa8e09718f843b7a32785fecb25e62bcde9b1cdf6cb9e6b4929d042a6fe0ef05
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90527);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/14");

  script_cve_id("CVE-2016-1361");
  script_osvdb_id(135782);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv17791");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw56900");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160311-gsr");

  script_name(english:"Cisco IOS XR GSR 12000 Port Range BFD DoS (cisco-sa-20160311-gsr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is a Gigabit Switch Router (GSR)
12000 Series router model and is a version that is missing a
vendor-supplied security patch. It is, therefore, affected by a denial
of service vulnerability in the ASIC UDP ingress receive function due
to improper validation for the presence of a Bidirectional Forwarding
Detection (BFD) header on the UDP packet. An unauthenticated, remote
attacker can exploit this to cause a line-card to unexpectedly restart
by sending to the affected device a specially crafted UDP packet with
a specific UDP port range and Time-to-Live field.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160311-gsr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07a86a86");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160311-gsr.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = FALSE;
override = FALSE;

cbi = "CSCuv17791 / CSCuw56900";

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model    = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");

if (model !~ "^12[0-9]{3}([^0-9])")
  audit(AUDIT_HOST_NOT, "Cisco 12000 Series");

# Specific versions affected according to Cisco
if (
  version =~ "^3\.3\.3([^0-9])"     ||
  version =~ "^3\.4\.[1-3]([^0-9])" ||
  version =~ "^3\.5\.[2-4]([^0-9])" ||
  version =~ "^3\.6\.[0-3]([^0-9])" ||
  version =~ "^3\.7\.[0-1]([^0-9])" ||
  version =~ "^3\.8\.[0-4]([^0-9])" ||
  version =~ "^3\.9\.[0-2]([^0-9])" ||
  version =~ "^4\.0\.[0-3]([^0-9])" ||
  version =~ "^4\.1\.[0-2]([^0-9])" ||
  version =~ "^4\.2\.[0-4]([^0-9])" ||
  version =~ "^4\.3\.[0-2]([^0-9])"
) flag = TRUE;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  # System has to contain serial network interfaces
  buf = get_kb_item("Host/Cisco/show_ver");
  if (!preg(multiline:TRUE, pattern:"^\d+\s+Serial network interface", string:buf))
    flag = FALSE;

  # Specifically bfd ipv6 checksum MUST be disabled to not be affected
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (flag && check_cisco_result(buf))
  {
    if(preg(multiline:TRUE, pattern:"^bfd ipv6 checksum disable", string:buf))
      flag = FALSE;
  }
  else if (flag && cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }
}

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

# The fix is to have 4.3.2 plus a vendor supplied SMU
# so 4.3.2 doesn't necessarily mean that the issue isn't
# fixed
if (flag && version =~ "^4\.3\.2([^0-9])" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release', 'Fixed version');
  report = make_array(
    order[0], cbi,
    order[1], version,
    order[2], '4.3.2 with Cisco SMU'
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}
security_note(port:0, extra:report+cisco_caveat(override));

