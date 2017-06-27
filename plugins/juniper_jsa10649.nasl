#TRUSTED 00350da21f344d03a99f9840a2c6d842c4c3cc9f74c5654276fc8a2ad9083c1d0adb464e8d226404b61e572a17544137d1ab0f3b38bc61d41398d7cc4e8a416fcdab6b22c0c6769f6c9f90fcc33c62ae8defc8933df52f74525bfa6f540c09ff74e4b0512d93fa3897f5f430fe75e988b9e1d6bb902690dae4f11e23635a2da19e9b45653c96dccdc0784d2730a7f67a68b528f8126d06985f85fab729b47c5856cd3df05b3ea33a7a7da0bd42fd65c9d304fa08ae6c1cdbc344f52cd3890b24af0c5e3c6bd49d5fdc1854dc90ee355930ca3ad9e55f98d693646a2c9faed7fe3bd11d7c60dd06d053158a2f88b42bfc9cc6ec2c2077c2d2b899dadde2f3cf3d28f03e20d07426d8e3721ba99dfc72bb8c62083e967258260d1eb6a93d31661c4aadbf229d5773461dd1c4f5bb166e4159cbbb0bcbba8d6fa3236cdb34e2f4ab36561a80271b7c9a1a59b467116d60f9fa9e9e05d56a2ede464e00900cbef5d7cc8c951cc83128aefec0285031a455445820c8fd634d539e42936ff434351962965e737ad3d8578aff7ec66495a59f3a76fa8340a4fba18c36428bf197a6e512a0ac5d19280a199928489b1511d561efa5128cacf08d4cc27081ba17e8f4a9d5d82106ba41256d1dd2974ad9ce7bee362f72a1fa1818bfe6e80763ef48ae1faf670c04c376427a82618fb5d62cfb85c6991448ac7dd510462631eb6d582e49a7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78420);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2014-3509",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(69077, 69079, 69083, 69084);
  script_osvdb_id(109896, 109897, 109898, 109902);
  script_xref(name:"JSA", value:"JSA10649");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10649)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by multiple vulnerabilities in the implementation of
OpenSSL :

  - An error exists related to 'ec point format extension'
    handling and multithreaded clients that allows freed
    memory to be overwritten during a resumed session.
    (CVE-2014-3509)

  - An error exists related to handling fragmented
    'ClientHello' messages that allows a man-in-the-middle
    attacker to force usage of TLS 1.0 regardless of higher
    protocol levels being supported by both the server and
    the client. (CVE-2014-3511)

  - A buffer overflow error exists related to handling
    Secure Remote Password protocol (SRP) parameters having
    unspecified impact. (CVE-2014-3512)

  - A NULL pointer dereference error exists related to
    handling Secure Remote Password protocol (SRP) that
    allows a malicious server to crash a client, resulting
    in a denial of service. (CVE-2014-5139)

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10649");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140806.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10649.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['13.3'] = '13.3R3-S2';
fixes['14.1'] = '14.1R2-S2';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (ver =~ "^13\.3[^0-9]")
  fix = "13.3R3-S2 or 13.3R4";
else if (ver =~ "^14\.1[^0-9]")
  fix = "14.1R2-S2 or 14.2R1";

# Check for J-Web or SSL service for JUNOScript (XNM-SSL)
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # J-Web HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
      override = FALSE;
  }
  if (override) exit(0, "Device is not affected based on its configuration.");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
