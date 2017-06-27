#TRUSTED 7c9e66dfc23a4abde722dbe71bb8fb3b74ecb3e6b38b97ca01e60a52ba2dad70a2dc8e29ab4081879cffadc715a2c8d27d8786da72d73c9d241d88a9b00836580812606de8fc1915f5da27db9683a38706687c27fa95a7ca64626f34a171c97764172db144dbdca2fcbc613950e724206f0dbe93d00a6ed1f126477582b0ed1dd6f2aa2997081a12c81aead3f3959370548f52a809ecc162a720fa2abf1889988c76bba7620c2529ed9ca4b73bf0dacffe00ad2475a1edf468fc590484f5b0030c82472f4fe52f6f05d4442b6bb1e1b53a3a646b598572d67be6afa921d001dc324c886db986643f25a707ccb387340519f7d404d2e9652c761592df475e76c75d16b31b9cddc7e7d3b7ef55cbd54d8b23c0c5d7cc4e80c61c0fbe0b9306ac50e713ad282789ccbf71c41ad071f0b7366527d332951d7e16381598445639e1dfdae2df06b456f2f1975db7f2f6191271dc46a4cbbd31b6f252630682505150f07dad08217bed2ef4888f4e402c1ea774f622ff426909ab403849d1b9469016c63f25c1fe680879ae1111aeeb112b6fb51543cd1d4f856713890112483572eaee47634ce5c0655764f4ecf251adb80820af89f2e4fba8da78a1a0112e64457b0513fa6da4a94d38c1b39bdbfd7f6a72934a58e0b5559dbff28d788e7cf07f0932e88b4ebfbea42fee832e72bc1a1b89c941e3809d81d06a5a704d06b4fc93fc29
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78064);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-5499");
  script_bugtraq_id(62866);
  script_osvdb_id(98165);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh46822");

  script_name(english:"Cisco IOS DHCP Remember Functionality DoS (CSCuh46822)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability when the remember
functionality of DHCP is enabled.

A flaw exists where the remember functionality does not correctly
handle the releasing of leases. An attacker can exploit this issue by
obtaining a lease and then releasing it, which may cause the device to
reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31156");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5499
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c52d7a3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuh46822.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

# Check for vuln version
if (version == '15.1GC') flag++;
else if (version == '15.1(4)GC') flag++;
else if (version == '15.1(4)GC1') flag++;
else if (version == '15.1M') flag++;
else if (version == '15.1(4)M') flag++;
else if (version == '15.1(4)M1') flag++;
else if (version == '15.1(4)M2') flag++;
else if (version == '15.1(4)M3') flag++;
else if (version == '15.1(4)M3a') flag++;
else if (version == '15.1(4)M4') flag++;
else if (version == '15.1(4)M5') flag++;
else if (version == '15.1(4)M6') flag++;
else if (version == '15.1(4)M7') flag++;
else if (version == '15.1T') flag++;
else if (version == '15.1(3)T') flag++;
else if (version == '15.1(3)T1') flag++;
else if (version == '15.1(3)T2') flag++;
else if (version == '15.1(3)T3') flag++;
else if (version == '15.1(3)T4') flag++;
else if (version == '15.1XB') flag++;
else if (version == '15.1(4)XB4') flag++;
else if (version == '15.1(4)XB5') flag++;
else if (version == '15.1(4)XB5a') flag++;
else if (version == '15.1(4)XB6') flag++;
else if (version == '15.1(4)XB7') flag++;
else if (version == '15.1(4)XB8') flag++;
else if (version == '15.1(4)XB8a') flag++;
else if (version == '15.2GC') flag++;
else if (version == '15.2(1)GC') flag++;
else if (version == '15.2(1)GC1') flag++;
else if (version == '15.2(1)GC2') flag++;
else if (version == '15.2(2)GC') flag++;
else if (version == '15.2(3)GC') flag++;
else if (version == '15.2(3)GC1') flag++;
else if (version == '15.2(4)GC') flag++;
else if (version == '15.2GCA') flag++;
else if (version == '15.2(3)GCA') flag++;
else if (version == '15.2(3)GCA1') flag++;

# Check for DHCP remember functionality enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ip dhcp remember", string:buf)) flag = 1;
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuh46822' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
