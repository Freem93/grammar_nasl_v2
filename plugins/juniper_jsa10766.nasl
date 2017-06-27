#TRUSTED 940e2718a42892bcb89e0f74347323956ebcdb16c9c68855029cd60da68a100a49fd3df61d024c9cd7f9665eed8ddbdf86699ca2a119949453be2dbf2a1981478ae4cf125d4ace7f26a74209165353bc7aabd164e01fdb56784280e624fb9a71e159578f981f88014aadbaa01d4564348312efdafc26c40e9fb9b1275d0df7933b20e5491ec2b18f1eadbbdd6173c3951d75e3b1bfffee7166d11957b568cbea7c0f0e283c9ef52d9a7342b398ae3ed4d0651dc9986f873654296bb56cb5e07077939551abe90ddc87d5721fb9fae2bbe36b87de1988c5e4acb7424803a61d33fed1bd15967cf9e02c1fc33bfd66edb13b239eb9655c1fb78a973e2e0e4c176600eb721e5e9860586bb81836be10e6d7065c47fb34606ec387e77f3235b9bfcb7b48b7b53402796d1b0fdf0c5105dbd2422565cd3e04971fc2dc60a71ac1989b5ca985b56ba0c76f54b4c282bd5ea6faab668bde6d2bc5fe6becb24f2cae98d3cddcd8d4ab7f3da28a8e9574bb498becc74ed831f27aa93a6b462fbb4193df8f25d81b74f3b9519f53222e49fff4a3a9bb1db5b8442607f6dc8fb820be5750e748c0c6862304d02d2285424f76e6e373b66f53285bb1f3cf6509c0a0e0be49129e3cca2252dc3d8a8a945b5902dd92a1b231240fa3287e87ef6af72dacbf29745f6422f09a6e72da693e5b33721935a9aeb52a7fe8e8fd8f498f3b038e75d6fa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94579);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/07");

  script_cve_id("CVE-2016-4924");
  script_bugtraq_id(93531);
  script_osvdb_id(145579);
  script_xref(name:"JSA", value:"JSA10766");
  script_xref(name:"IAVA", value:"2016-A-0295");

  script_name(english:"Juniper Junos vMX 14.1 < 14.1R8 / 15.1 < 15.1F5 Local Information Disclosure (JSA10766)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and architecture, the
remote Juniper Junos vMX (Virtual MX Series) router is 14.1 prior to
14.1R8 or 15.1 prior to 15.1F5. It is, therefore, affected by a local
information disclosure vulnerability due to the use of incorrect
permissions. A local attacker can exploit this to disclose sensitive
information in vMX or vPFE images, including private cryptographic
keys.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10766");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper Junos vMX 14.1R8 / 15.1F5 as referenced in Juniper
advisory JSA10766.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:vmx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
if(model != "VMX") audit(AUDIT_HOST_NOT, "a Juniper vMX device");

if(ver !~ "^1[45]\.1") audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

match = ereg_replace(string:ver, pattern:'^(([0-9]+\\.[0-9]+)(?:([A-Z])([0-9]+))?(\\.([0-9]+))?)(?:-[0-9.]+)?$', replace:"\1");
if(!empty_or_null(match)) ver = match;

fixes = make_array();
fixes['14.1'] = '14.1R8';
fixes['15.1F'] = '15.1F5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
