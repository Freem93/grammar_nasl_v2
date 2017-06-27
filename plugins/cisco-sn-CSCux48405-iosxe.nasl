#TRUSTED 60017709e28ca1829de5a276ed68113807fe7b1d1bbc541d4752e273cd4f4ccf965abe271260c262a41477ac1525957bff743a826ff70df66b965bffb65b0f38558ded5b04aec2ef4b2f88a3d6d80cf31d506edfe6f8ea60f900fb79aca1e6f17fb4894eaaa9c4a18b377cfb3cc6ce8ab29b536584e4d4a217f99396ffaf13e7b7fdf8ae7504aa6f6cb102735f1b78c76dc8f7c5173d0ff0d63b30c477ee09dbea9471b650aa9aa2e54d4fde1d72de98a0d9bcd3606aec9be52ed70ebf72b2af761aeec185a9d6c7adb4a64c61f19b385e6ff32686eb960d7b9cfc6db673cf2a2c854a82a8eb6f9287d362099476f0164a667bf79ecc99eef0e11123bb8be39cfa5db402b1cb385b8a37015d1d0dbf5f0f169716fda123a06d777c5f42d655f403a99ee1b6517011d2dbfbb45731c568ded7d7f6e4e6cfb01e80cbf227ab4d52b3774b60caef2ba7195f2284f8e40e540ef44d5531375f512a6291ea6568b54444b0294c7e0bcfe74a88b91cce6ec1a49b164b259cbe7b4118e7d39f6803494ce636abcb0254b481d5bd467a027ad39d14bcc425e3342d23aca9a4483cae72c2c3ace3d959a7a7a40ef1bb5eb75bab2666ed113e56cbf91e84307df1f7c98ac54296acd6b7cd709f09be058db4fa751dff8da41b81b223193f7113f64b10d5a01bfc996270638aa75911074367b462a90d994f55501828a5d2a7adf5df20f2bb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87847);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/10");

  script_cve_id("CVE-2015-6431");
  script_bugtraq_id(79654);
  script_osvdb_id(132128);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux48405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-2015-1221-iosxe");

  script_name(english:"Cisco IOS XE Source MAC Address DoS (CSCux48405)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is Release 16.1.1. It is, therefore,
affected by a denial of service vulnerability due to incorrect
processing of packets that have 0000:0000:0000 as a source MAC
address. An unauthenticated, adjacent attacker can exploit this to
cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-2015-1221-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0bd5b5f");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCux48405");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

# Check for the single vulnerable version
# 16.1.1
if (
  ver =~ "^16\.1\.1$"
)
{
  flag++;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux48405' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report );
    exit(0);
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
