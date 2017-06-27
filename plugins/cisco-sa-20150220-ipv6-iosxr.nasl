#TRUSTED 7402c0dc50a1f10bfb5e321f5344e2a7bc70ee577ab9704546ce23a84f47e6e721703ad92856060bd79ca0c35780e5068467586a55bf55f631084fff2b0972582a016da71660dbd5b8c0e1161a271ec6c70216520451394f90d7632563e90256e14c0817c6db3db2e5dcf8db0fc532a2d9550ac8052c3e6916750314beac38883cb4c7675cea5ae377534e516b5369eb14432f8c8216e6131c036194d992401a5b612ba8e5274e25caaaf9121d1d72974bbb2b9f5a4aeea679ed4b475b3f3cb4db966a7731df4cf619660b330016be51b80e5e0e5d769e56d8b27a5d728e08982c32741c3e07214dc5c806486ec983d64d5aa337ee86ac906151f5e6ebfdbddb6985012d867129d23b3b2d6d8972534c67f33a89b61c1ff0d1624304629112ad310cc1cf4d97d71f484287bbbd401bd1c0916c9420d0414b3bcddec5c0ed563430d40e017308840a67eef997cced7f7af22f8689bc1c4b883a3c83e8bcf430096897bbe551ecdbbcff4d7c51dcd73198db8c2a79ef1be572d6ba8056e8d55376aeff841e21960571cc0c3dacbaa69c485caef229815e393cc04ee0ce8caed489ac9028c5b78cf3d03303ab3667004b6996d1c75e738da5b4242aa897b178d132c2d60da501b32bc8f3a4e77d8821296a1d10e8fc333e2bb0cdc6bfc9380587e72e363a763787d8f80948a9a35ffd84f48261b95433b4f249c17df77d263b75e8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82498);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0618");
  script_bugtraq_id(72713);
  script_osvdb_id(118631);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq95241");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150220-ipv6");

  script_name(english:"Cisco IOS XR IPv6 Extension Header DoS (cisco-sa-20150220-ipv6)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to improper processing of malformed IPv6 packets
carrying extension headers. A remote attacker, using a specially
crafted packet, can cause a reload of the line card, resulting in a
denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150220-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc11e4ce");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37510");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150220-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

cbi = "CSCuq95241";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model   = get_kb_item("CISCO/model");

if (model)
{
  if (
    tolower(model) !~ "^cisconcs(6008|6k)"
    &&
    tolower(model) !~ "^ciscocrs-?x"
  ) audit(AUDIT_HOST_NOT, "a Cisco NCS 6000 or CRS-X device");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
    &&
    "CRS-X"   >!< model
    &&
    "CRSX"   >!< model
  ) audit(AUDIT_HOST_NOT, "a Cisco NCS 6000 or CRS-X device");
}

if (cisco_gen_ver_compare(a:version, b:"5.0.0") >= 0)
{
  # NCS 6k models
  if (
    tolower(model) >< "ncs"
    &&
    cisco_gen_ver_compare(a:version, b:"5.2.3") == -1
  )
  {
    flag++;
    fixed_ver =
      'upgrade to 5.2.3 or later, or consult' +
      '\ncisco-sa-20150220-ipv6 regarding patches.';
  }

  # CRS-X models
  if
  (
    tolower(model) =~ "crs-?x"
    &&
    cisco_gen_ver_compare(a:version, b:"5.3.0") == -1
  )
  {
    flag++;
    fixed_ver = "5.3.0";
  }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");

    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
