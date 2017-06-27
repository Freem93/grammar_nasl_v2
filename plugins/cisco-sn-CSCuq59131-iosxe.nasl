#TRUSTED 40c2adb90ea888751f9f306de8259c84ed34b842b1a3d5627034b0349c77a30355ebd0c95df9c475055e90264b5c73b3e2089d616bc2efb21181a4a6f53a9f67cdb75d7b18ada83f119e5f48018735d4ae92f8a33886fee1bf050b4060c8be990dc695460315a8e3a94b4f510233fca3dcc22b4f9af89570a33e621cd030ea1fb0bf30d04b2f97b73c0e4e56e7f5ad8b93fbf02ae5f7d626ae1e08b066aabc09d77d173abd9ff51dc613561df80747760603ac68ba0aae46f16bd6f4be2313666b99512da1ff41a53da964c5ab55354437b9cdfb8db5a4e1127e52d328ed284673d6932460e522176426da9fc788855abb2cd4d998ba47efb6696f64d19f3d1f41a09501aeb766ac3d2d19285271a5f620da9ddfaa788725687e7b216789cca939902126a48da1cf626a2857c2ff7c8b7ec487c1c46741461faaf6242ef715c16fe6839e09c1cc71223d044af016999f2513686301b0b2e92beb573ef9e58a4725e7665363a0910f6b6f968e4e6c5fea0258e48e51c41cc351dcd2b910d9c070a194cbbd50d55ba2d72c55ecd178cd8cbcc44681adf3e4a15b402a203676222ddde6aab7624f3b9f60b66ac49c7c0cbc01637378bffc9489f9dcecaf3bbb58434e3da2a46cda7ce00849b1b7d02dea97f6caae3d9be1b77539c5cd80282e3c115596102fe91d995e2248f96776012650158215bf721a94912898c99650bb4fe3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82590);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0645");
  script_bugtraq_id(73337);
  script_osvdb_id(119944);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq59131");

  script_name(english:"Cisco IOS XE Layer 4 Redirect DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper processing of IP
packets by the Layer 4 Redirect (L4R) feature. An unauthenticated,
remote attacker, using crafted IPv4 or IPv6 packets, can exploit this
to cause a device reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea0b29");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuq59131");
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

# Bug
if (version == "15.2(4)S0.1") flag++; # Not in map

# CVRF
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.0S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.13.0S")  flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.4.0S")   flag++;
if (version == "3.4.1S")   flag++;
if (version == "3.4.2S")   flag++;
if (version == "3.4.3S")   flag++;
if (version == "3.4.4S")   flag++;
if (version == "3.4.5S")   flag++;
if (version == "3.4.6S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.[789]($|[^0-9])") flag++;

# Check L4 Redirect config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+redirect server-group ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^\s+redirect to group ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuq59131' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
