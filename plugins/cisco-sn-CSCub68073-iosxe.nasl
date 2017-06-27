#TRUSTED 0a334f33abbaaf1dcda15ce029d9e8874a617335859e7d3ed6ced9de08a5f8c2ed57ab34941cde1ef092e8f253090c5b81d42c5979804f02ee9537a7a32e2242926d9a1a650b681ba876eea07acc2ec96b6175190fb772600283554889ae6b8addfbff948e68484be1b144a37f11e12461df1e0e171bf288fc12fb491e320c840d087b7fcbe45b99284b6208048603579cb259ae49bd21319c52c97116c7614e20bd657056e93b4b766d4605e4a6b34d75bf5f068de5f7a765676578623fbc450ee1793c90de9efafd6da81d0eef1bdacdaaf9a9e00e0e9466a50589f0d0bacf3b615bfa36c27f344bc77474a2f2c6c0ef247e3528e8fbd962e4a0d7b19dfafaaa71c9d8b3094e3bd2bcdd9207098a766e82dbdb6f36e530020ba5463e8b3feba86363e885b03dae99b5039f6133af037e678682bcbf7bf281bfd8d317d82b6f09ddc593530c6f20df57256350c69edaffc1ccc65a1c33f80195854eb5112954f456c3dc32438d79f9f3b82aab6e4fb0d4c3717170b43d8472d02f34912176b158ed106ad316a4a41daf3e25fcd6412bc2aceba9c77787950ef910677461b65c9c5ea6c7aedc284af51486abb74393ebafc31375914e89954c699798b466497e54336d61cb3ebabfc74305a014135389259d9ce2dfe6c806b92b8cb52b8d4b6a72fd2be0ccd4dd9a148e9dbedcb917fd17daef3d23ba752b6c5908176f014faf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82587);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0641");
  script_bugtraq_id(73337);
  script_osvdb_id(119943);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub68073");

  script_name(english:"Cisco IOS XE IPv6 DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper parsing of IPv6
packets. An unauthenticated, remote attacker, using crafted IPv6
packets, can exploit this to cause a device reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea0b29");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCub68073");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# CVRF
if (version == "3.1.0S") flag++;
if (version == "3.1.1S") flag++;
if (version == "3.1.2S") flag++;
if (version == "3.1.3S") flag++;
if (version == "3.1.4S") flag++;
if (version == "3.1.5S") flag++;
if (version == "3.1.6S") flag++;
if (version == "3.2.0S") flag++;
if (version == "3.2.1S") flag++;
if (version == "3.2.2S") flag++;
if (version == "3.2.3S") flag++;
if (version == "3.3.0S") flag++;
if (version == "3.3.1S") flag++;
if (version == "3.3.2S") flag++;
if (version == "3.4.0S") flag++;
if (version == "3.4.1S") flag++;
if (version == "3.4.2S") flag++;
if (version == "3.4.3S") flag++;
if (version == "3.4.4S") flag++;
if (version == "3.4.5S") flag++;
if (version == "3.4.6S") flag++;
if (version == "3.5.0S") flag++;
if (version == "3.5.1S") flag++;
if (version == "3.5.2S") flag++;
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.0S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;
if (version == "3.7.6S") flag++;
if (version == "3.7.7S") flag++;
if (version == "3.8.0S") flag++;
if (version == "3.8.1S") flag++;
if (version == "3.8.2S") flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ipv6 address ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ipv6 enable ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCub68073' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
