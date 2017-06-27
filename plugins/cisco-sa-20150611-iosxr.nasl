#TRUSTED 822427bcc2462fe31563f9d590c0162f8ae934cd30bd44174568985882f790f9fb09ea0a34cda04af15339e539a78f8538b0bbf86a0c1846509f38f21e4bf4560306a298eca6ce9d4df6186d0efa0aa1841004a1aa7551267258d0e5bd231dff01bfe17cbef0bd029f3e9193abcd8a100090f4d9958e81c005ff0996219b075789fa15da04d1be0bac8b4b263570c8cea432676cc1ec8e7a593ed355089b3206b70d52a905b15126f8403f8bf1bef02f68fe90fbc9d5ebbd9e674ab43a9e9ddfe8c5b06e0c9a2deed2f3a235828087b9b20ac53fb153d1f8d3d32df4e3b2b37dbe4d73f24d7c008abe564f26ddc42932858febdcc476a5453bbcb8cd6eeada990dd44b4566a1199dc62c2e1823ea864430756914e01c4c017f55c901f981f9d892e30fd8928ac06c8b5fa5df8459caac1afb372369b6e369093ffb99a193f1d9206eab02294aff3471650d9fbde4fcd9babe50ad3d94c30e9a17f506ef09cda5cc8552bc529004081cc2a0d05bc97184c199a08811bcd348fa9ca03ca740a2521afb80fef23f3112849f2d9e85ce193198d830fe528fac3147646a4d70a55dce7813296ba9f8a78b31196f4bf5a272f5b8b7a770bed44a926a8421a1ab1fe1d0c09cd237c4b41298f6fe5356bfba7726c293c846a2dda5b8dd9836fd5c3ed2a5b55d85436923ab7aab2b5c86f87ce0a9eb55275a0bbdf1fc8cbff790ad224cc4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84287);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/01/10");

  script_cve_id("CVE-2015-0769");
  script_bugtraq_id(75155);
  script_osvdb_id(123205);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx03546");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150611-iosxr");

  script_name(english:"Cisco IOS XR Software Crafted IPv6 Packet DoS (cisco-sa-20150611-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to improper processing of IPv6 packets carrying
extension headers that are otherwise valid but are unlikely to occur
during normal operation. A remote attacker, using a specially crafted
packet, can cause a reload of the line card, resulting in a denial of
service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150611-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d13419b7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150611-iosxr.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCtx03546";
fixed_ver = "";
reason = "";

# Cisco SMUs per version (where available)
pies = make_array(
  '4.1.0', 'hfr-px-4.1.0.CSCtx03546',
  '4.1.1', 'hfr-px-4.1.1.CSCtx03546',
  '4.1.2', 'hfr-px-4.1.2.CSCtx03546',
  '4.2.0', 'hfr-px-4.2.0.CSCtx03546'
);

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model   = get_kb_item("CISCO/model");

if (model)
{
  if (tolower(model) !~ "^ciscocrs-3($|[^0-9])")
    audit(AUDIT_HOST_NOT, "a Cisco CRS-3 device");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (tolower(model) !~ "^cisco crs-3($|[^0-9])")
    audit(AUDIT_HOST_NOT, "a Cisco CRS-3 device");
}

# set our fixed version based on the version detected
if (version =~ "^4\.0\.[1-4]")
{
  flag++;
  fixed_ver = "4.2.1";
}
else if (!isnull(pies[version]))
{
  flag++;
  fixed_ver = version + " with patch " + pies[version];
  if (get_kb_item("Host/local_checks_enabled"))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >< buf)
        audit(AUDIT_HOST_NOT, "affected since patch "+pies[version]+" is installed");
    }
    else if (cisco_needs_enable(buf)) override = 1;
  }
}

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    # if we have an affected card
    if (preg(multiline:TRUE, pattern:"CRS-MSC-140G", string:buf) ||
        preg(multiline:TRUE, pattern:"CRS-FP140", string:buf) ||
        preg(multiline:TRUE, pattern:"CRS-LSP", string:buf))
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf2))
        {
          # and we have ipv6 enabled
          flag = 1;
        }
        else reason = " since IPv6 isn't enabled";
      }
      else if (cisco_needs_enable(buf2))
      {
        flag = 1;
        override = 1;
      }
    }
    else reason = " since an affected line card is not installed on the chassis";
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
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
else audit(AUDIT_HOST_NOT, "affected" + reason);
