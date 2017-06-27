#TRUSTED 11712c622d0e958444ad7bb2ed3be6bb844fa717b062c86e0d446a769bf59dbf32769752adfd9632eca73ef0538350842edcaa3ebb181ffb93dda1a58ef96e9c5c96cedf82defb710c3ae826b3e487f454cda387cf34a1b03a6dcb92aedf5b116099a8975704b37e608e78cfeb6fa7f5c0d59baa9170e51fd5669b418bba69e0da887c79ec28c19b3410ee620f81b45e2db9ce44e4b418437dc9de5fc21f4217a81a376441c6577fc1ede6768e9dde6205700b502b5910ed0495256b3c1a7edef60613a7c0d83a5af2501cdf8846ba32800681e16ab1a113f0cad8cb61d8be4588b3711353b421371bd29d0f19963178c72b7fb4bee01f25f0d0a6bd468cea22ec4be110338494b3aaeb2f00d75536da3da91e886581c6cb3ec157f469cf581f45d8ece2c550db627f930083cc95bb2388331d89a33aa641a1897bba872f00ee3de24277391192e661811fc4b9a34bd90aaf0dd3c99bf7aa4bd3e5bbd7bd5ed8f8245734114d64523edf88063c086608fc83d0a8a32ee2c17b8791c63f19d2e03b0f806eca14009404277f7c1d5bb61c1f53409b4522f6952657a6d3516a6af993b0d89fca49f27fa92ad9c579828987f762ea49f473cdf26f2cf7d69c95b12dc6791323bc612e548f3d0e972009793c95944e41e2111a0a6e680067b64ea11e9ae7e25c9edb94151bf025ec87b0ea781c11be3637ec9b2b848cdde1fef93ad2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87504);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/29");

  script_cve_id("CVE-2015-6359");
  script_bugtraq_id(79200);
  script_osvdb_id(131776);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup28217");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151214-ios");

  script_name(english:"Cisco IOS XE Software IPv6 Neighbor Discovery DoS (CSCup28217)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is not configured to limit the IPv6 neighbor discovery (ND)
cache. It is, therefore, affected by a denial of service vulnerability
due to insufficient bounds on internal tables. An unauthenticated,
adjacent attacker can exploit this, via a continuous stream of ND
messages, to exhaust available memory resources, resulting in a denial
of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151214-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?534beecb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup28217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup28217.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if ( "ASR" >!< model ) audit(AUDIT_HOST_NOT, "affected");

flag     = 0;
override = FALSE;

if (
  version =~ '^[0-2]\\.' ||
  version =~ '^3\\.([0-9]|1[0-4])\\.' ||
  version =~ '^3\\.15\\.[01]($|[^0-9])' ||
  version =~ '^3\\.16\\.0($|[^0-9])'
) flag = 1;
else audit(AUDIT_HOST_NOT, "affected");

if (flag && get_kb_item("Host/local_checks_enabled") && (report_paranoia < 2))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("ipv6 nd cache interface-limit" >!< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup28217' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
} else audit(AUDIT_HOST_NOT, "affected");
