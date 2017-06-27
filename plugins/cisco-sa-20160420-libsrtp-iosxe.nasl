#TRUSTED 177cfe1685aa782a5d0b5cd2f76bf0a007a695fbd78faed2f23e96d0ed4c038d6af439ad425c93f844997bcc67f72796ca9d4168fe487ed0e01b9a41f716322e22fabe72421bf89e24aa2f96eddd66afb6ac40164993799219ff6aa02714cbee6ee940fb38d8c18114e1293e98d0b73caad13087a8d598b4278ab85ba4e5a0ec290f7bde1970c16e08b266f56c1d0f4b57ea1ae6832b64d67e7b061628cb3890c9c9a108f0a79c846eecfb3e112cc9313fff21012f3acd4feba89f09df81c1044df09dd951950de136c1f22ac9cd37129e39d42dcbdc0921f97ea05535b7fd7bd2a053fd11607bb511e85fb469ba8fc0f150f8b4adc80f3986eda72d6255d0293b3de23fdae73b9837dcd270ed3a0d6918394d042378bf549d18b58d685c3e5d0cb6b158ca3ae1fb6af930af03fc9edf8e9e5a24faae852df1fe2738b560417b35c1c1b8cd11dd02ad8865045db781ddf71c96208ebb039cfce1d9573ec2dd094120d27fd31f4a1f62ac7997648b289e7acdac920527b918a3b3e53325e154630ee314e9d5231b7536b9fc51680e50ffc425a696e60f1dc12a5a9335164956c3dd94c3a8334b781058ddc2eb4641e27cbf14e0ff5b51cbdcbdd6ed1486e0cc6351cd69dec6b8206f2ca8e3f4dd6a514fe5debc6715087da6462ee7eb5c88faa8b3f7c3f644e82cdf35a4a4674828f246c0069d0920c125194b35af2d401a4f96
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91760);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/22");

  script_cve_id("CVE-2015-6360");
  script_osvdb_id(131631);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux04317");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco IOS XE libsrtp DoS (CSCux04317)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and it is configured to use the Cisco Unified Border Element
(CUBE) or Session Border Controller (SBC) features. It is, therefore,
affected by an integer underflow condition in the Secure Real-Time
Transport Protocol (SRTP) library due to improper validation of
certain fields of SRTP packets. An unauthenticated, remote attacker
can exploit this, via specially crafted SRTP packets, to cause packet
decryption to fail, resulting in a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cb183fe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20160420-libsrtp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

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

flag = FALSE;
override = FALSE;

# Fixed: 3.14.3S, 3.13.5S, 3.16.2S, 3.10.7S, 3.17.1S, 3.15.3S
# Check for vuln version

if ( ver == "3.10.01S" ) flag = TRUE;
if ( ver == "3.10.0S" ) flag = TRUE;
if ( ver == "3.10.0aS" ) flag = TRUE;
if ( ver == "3.10.1S" ) flag = TRUE;
if ( ver == "3.10.1xbS" ) flag = TRUE;
if ( ver == "3.10.2S" ) flag = TRUE;
if ( ver == "3.10.2aS" ) flag = TRUE;
if ( ver == "3.10.2tS" ) flag = TRUE;
if ( ver == "3.10.3S" ) flag = TRUE;
if ( ver == "3.10.4S" ) flag = TRUE;
if ( ver == "3.10.5S" ) flag = TRUE;
if ( ver == "3.10.6S" ) flag = TRUE;
if ( ver == "3.13.0S" ) flag = TRUE;
if ( ver == "3.13.0aS" ) flag = TRUE;
if ( ver == "3.13.1S" ) flag = TRUE;
if ( ver == "3.13.2S" ) flag = TRUE;
if ( ver == "3.13.2aS" ) flag = TRUE;
if ( ver == "3.13.3S" ) flag = TRUE;
if ( ver == "3.13.4S" ) flag = TRUE;
if ( ver == "3.14.0S" ) flag = TRUE;
if ( ver == "3.14.1S" ) flag = TRUE;
if ( ver == "3.14.2S" ) flag = TRUE;
if ( ver == "3.15.0S" ) flag = TRUE;
if ( ver == "3.15.1S" ) flag = TRUE;
if ( ver == "3.15.1cS" ) flag = TRUE;
if ( ver == "3.15.2S" ) flag = TRUE;
if ( ver == "3.16.0S" ) flag = TRUE;
if ( ver == "3.16.0aS" ) flag = TRUE;
if ( ver == "3.16.0bS" ) flag = TRUE;
if ( ver == "3.16.0cS" ) flag = TRUE;
if ( ver == "3.16.1S" ) flag = TRUE;
if ( ver == "3.16.1aS" ) flag = TRUE;
if ( ver == "3.17.0S" ) flag = TRUE;

# Check for Smart Install client feature or support of archive download-sw
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_sbc", "show running-config | include sbc");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"^\s*sbc [^\s]+", multiline:TRUE)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }

  if(!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_srtp-auth", "show running-config | include srtp-auth");
    if (check_cisco_result(buf))
    {
      if (preg(string:buf, pattern:"^\s*(|voice-class sip )srtp-auth( [^\s]+|$)", multiline:TRUE)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = TRUE;
      override = TRUE;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux04317' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
