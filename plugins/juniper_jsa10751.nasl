#TRUSTED 2639bea256aa87596211274749c1296e9587f372fe9ae44fb60d82d90343aa243e26a9ac12a35e5c4a1733f4bc73208182462520a43b6ae0bca52009d32df6b5fe71307d3156b4c859a24c6818cc9bb672a192f33e27a44fe073f14627720e9aaab02ee4d46ae8d06104de265c1bbd33c105d35a4bd586c50dd320babb9517e2c72ec08210ae7be8d12dc53a0a72f1b151e395ed9bb7f6dde0aadd9bb4f1dd76bf87b06a168dcccb594f160eae2b8f12ea9d8e83d6e85f14551fde2557a84250180cb1765f5c7317b407fb39b80ef7f25b8971cceb65cf2afc104d92a86089425fa2b36d8783b20d86765d21dffe2b1fbb8deb0e2bf769df19081405671748fa5d5d38587996395e779ed17136c7b552bcebe0f9d5cd29b2a182eb7397070a96e895274f6ef97dc45edc022ded6a22486767b825661dc7c6e5ed638e4d009f677ac1223a4946382f32552823c0eca0bc5263ef82ecb85082629c9563536b8a0607421bc02ecd80a07b439539fc0577cc2383dc119b01d0694f496567e9168d39f211a9b5537663c281e839cbe7bf323da74338231ef3f0cef5f72cc97e28a73cc89a1949b79a4c12f9420b0d16d4cf22cc42c6bf351664a804885398f50046aa5854267eca6eb7d6147e156ea7db3f643b3bddd766ece81582c53be8ffde76ee3fd5eec6484b8da87299fed79d7c718b5d1dfe0db374e4a4419eb57fc9e14e6d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92519);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/25");

  script_cve_id("CVE-2016-1276");
  script_osvdb_id(141474);
  script_xref(name:"JSA", value:"JSA10751");

  script_name(english:"Juniper Junos SRX Series Application Layer Gateway DoS (JSA10751)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the application layer gateway (ALG) that is triggered
when matching in-transit traffic. An unauthenticated, remote attacker
can exploit this to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10751");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10751. Alternatively, disable all ALGs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D23'; # or 12.1X47-D35
fixes['12.3X48'] = '12.3X48-D25';
fixes['15.1X49'] = '15.1X49-D40';

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X47-D23")
  fix += " or 12.1X47-D35";

override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^.*:\s*Enabled";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no ALGs are enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
