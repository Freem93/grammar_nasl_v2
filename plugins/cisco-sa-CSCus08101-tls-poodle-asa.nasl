#TRUSTED ad2dd957727ee94e5be623ef9400a9acdcf0f307f1cb7f0949a26473dd1fbba4bba3d032fc9008589709a66101b007d9b70366b135bf3bee8df0b00e4a4c8150b454b583996f7492aa4128b2e5d420043065a39df17c3f78fab9c83e4ef071f2b9a7bbd7e3fcbbcda0ba2660a1099f19f3cbc0034474cc21e2fe089e09f60f22ecbf830520e5285db56e49e1bffdfb728eb0d398d276ac6d3daed6a53670ab6014dbd675b174732bcdef7d5ff3882c73d9a5b07720dbdfbcedf94a26fd2c77976dcc0c450358975025c88b1888ba163dd869877b0bb831459ef7637a2bdab732eb51a3aa79c05402ed686560d0b5a727c67eb33f555d5be33124e05c722d7044db10cba0f63d8eb2729be1c861d5f66d7348c96a8086c71cf16eeaf0b3980cdfe387a7f4c9f68d2c139aaa4b3f275b98b97afb94fff25ccc07c98b43f80ac9587c36bbed306c0f279e740e473172654a185791a26d6ecba4078cf8fa8e83876bd88f5173086f4ee72ec821180f5e2941b296942866df5f219960e049563be32bad9e7d977608067a58fdc36f43b5d8d53ac18de5a0afb59c9fbce8e2e94374fe72582195d10273a33cd075640ceaee4ed5579039da009d9b7190e00b00ccd4b8e4b18440ea8624173cc8730e0c341294477b5e8912dadf73ffbb7d84526affa1ed24565e812c4e994f9661ac1c3a858011bc73b2c73b0e6b3bbe6a6cd3a4bd23
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82429);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_osvdb_id(115953);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus08101");

  script_name(english:"Cisco ASA TLS CBC Information Disclosure (CSCus08101)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Cisco ASA software on the
remote device is affected by an information disclosure vulnerability
due to improper block cipher padding by TLSv1 when using Cipher Block
Chaining (CBC) mode. A remote attacker, via an 'Oracle Padding' side
channel attack, can exploit this vulnerability to gain access to
sensitive information. Note that this is a variation of the POODLE
attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/12/08/poodleagain.html");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus08101");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=36740");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver   = extract_asa_version(asa);

if (isnull(ver))
  audit(AUDIT_FN_FAIL, 'extract_asa_version');

# ASAv shows model == 'v'; ignore here as well.
if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500 or 5500-X');

fixed_ver = NULL;

# Affected version list from advisory
versions = make_list(
  "7.0.0",
  "7.0.1",
  "7.0.1.4",
  "7.0.2",
  "7.0.3",
  "7.0.4",
  "7.0.4.2",
  "7.0.5",
  "7.0.5.12",
  "7.0.6",
  "7.0.6.18",
  "7.0.6.22",
  "7.0.6.26",
  "7.0.6.29",
  "7.0.6.32",
  "7.0.6.4",
  "7.0.6.8",
  "7.0.7",
  "7.0.7.1",
  "7.0.7.12",
  "7.0.7.4",
  "7.0.7.9",
  "7.0.8",
  "7.0.8.12",
  "7.0.8.13",
  "7.0.8.2",
  "7.0.8.8",
  "7.1.0",
  "7.1.2",
  "7.1.2.16",
  "7.1.2.20",
  "7.1.2.24",
  "7.1.2.28",
  "7.1.2.38",
  "7.1.2.42",
  "7.1.2.46",
  "7.1.2.49",
  "7.1.2.53",
  "7.1.2.61",
  "7.1.2.64",
  "7.1.2.72",
  "7.1.2.81",
  "7.2.0",
  "7.2.1",
  "7.2.1.13",
  "7.2.1.19",
  "7.2.1.24",
  "7.2.1.9",
  "7.2.2",
  "7.2.2.10",
  "7.2.2.14",
  "7.2.2.18",
  "7.2.2.19",
  "7.2.2.22",
  "7.2.2.34",
  "7.2.2.6",
  "7.2.3",
  "7.2.3.1",
  "7.2.3.12",
  "7.2.3.16",
  "7.2.4",
  "7.2.4.18",
  "7.2.4.25",
  "7.2.4.27",
  "7.2.4.30",
  "7.2.4.33",
  "7.2.4.6",
  "7.2.4.9",
  "7.2.5",
  "7.2.5.10",
  "7.2.5.12",
  "7.2.5.2",
  "7.2.5.4",
  "7.2.5.7",
  "7.2.5.8",
  "8.0.0",
  "8.0.1.2",
  "8.0.2",
  "8.0.2.11",
  "8.0.2.15",
  "8.0.3",
  "8.0.3.12",
  "8.0.3.19",
  "8.0.3.6",
  "8.0.4",
  "8.0.4.16",
  "8.0.4.23",
  "8.0.4.25",
  "8.0.4.28",
  "8.0.4.3",
  "8.0.4.31",
  "8.0.4.32",
  "8.0.4.33",
  "8.0.4.9",
  "8.0.5",
  "8.0.5.20",
  "8.0.5.23",
  "8.0.5.25",
  "8.0.5.27",
  "8.0.5.28",
  "8.0.5.31",
  "8.1.0",
  "8.1.1",
  "8.1.1.6",
  "8.1.2",
  "8.1.2.13",
  "8.1.2.15",
  "8.1.2.16",
  "8.1.2.19",
  "8.1.2.23",
  "8.1.2.24",
  "8.1.2.49",
  "8.1.2.50",
  "8.1.2.55",
  "8.1.2.56",
  "8.2.0",
  "8.2.0.45",
  "8.2.1",
  "8.2.1.11",
  "8.2.2",
  "8.2.2.10",
  "8.2.2.12",
  "8.2.2.16",
  "8.2.2.17",
  "8.2.2.9",
  "8.2.3",
  "8.2.4",
  "8.2.4.1",
  "8.2.4.4",
  "8.2.5",
  "8.2.5.13",
  "8.2.5.22",
  "8.2.5.26",
  "8.2.5.33",
  "8.2.5.40",
  "8.2.5.41",
  "8.2.5.46",
  "8.2.5.48",
  "8.2.5.50",
  "8.3.0",
  "8.3.1",
  "8.3.1.1",
  "8.3.1.4",
  "8.3.1.6",
  "8.3.2",
  "8.3.2.13",
  "8.3.2.23",
  "8.3.2.25",
  "8.3.2.31",
  "8.3.2.33",
  "8.3.2.34",
  "8.3.2.37",
  "8.3.2.39",
  "8.3.2.4",
  "8.3.2.40",
  "8.3.2.41",
  "8.4.0",
  "8.4.1",
  "8.4.1.11",
  "8.4.1.3",
  "8.4.2",
  "8.4.2.1",
  "8.4.2.8",
  "8.4.3",
  "8.4.3.8",
  "8.4.3.9",
  "8.4.4",
  "8.4.4.1",
  "8.4.4.3",
  "8.4.4.5",
  "8.4.4.9",
  "8.4.5",
  "8.4.5.6",
  "8.4.6",
  "8.4.7",
  "8.4.7.15",
  "8.4.7.22",
  "8.4.7.23",
  "8.4.7.3",
  "8.5.0",
  "8.5.1",
  "8.5.1.1",
  "8.5.1.14",
  "8.5.1.17",
  "8.5.1.18",
  "8.5.1.19",
  "8.5.1.21",
  "8.5.1.6",
  "8.5.1.7",
  "8.6.0",
  "8.6.1",
  "8.6.1",
  "8.6.1.1",
  "8.6.1.10",
  "8.6.1.12",
  "8.6.1.13",
  "8.6.1.14",
  "8.6.1.2",
  "8.6.1.5",
  "8.7.0",
  "8.7.1",
  "8.7.1.1",
  "8.7.1.11",
  "8.7.1.13",
  "8.7.1.3",
  "8.7.1.4",
  "8.7.1.7",
  "8.7.1.8",
  "9.0.0",
  "9.0.1",
  "9.0.2",
  "9.0.2.10",
  "9.0.3",
  "9.0.3.6",
  "9.0.3.8",
  "9.0.4",
  "9.0.4.1",
  "9.0.4.17",
  "9.0.4.20",
  "9.0.4.24",
  "9.0.4.5",
  "9.0.4.7",
  "9.1.0",
  "9.1.1",
  "9.1.1.4",
  "9.1.2",
  "9.1.2.8",
  "9.1.3",
  "9.1.3.2",
  "9.1.4",
  "9.1.4.5",
  "9.1.5",
  "9.1.5",
  "9.1.5.10",
  "9.1.5.12",
  "9.1.5.15",
  "9.1.5.19",
  "9.2.0",
  "9.2.1",
  "9.2.2",
  "9.2.2.4",
  "9.2.2.7",
  "9.2.2.8",
  "9.2.3",
  "9.3.0",
  "9.3.1",
  "9.3.1.1",
  "9.3.2"
);

foreach version (versions)
{
  if (cisco_gen_ver_compare(a:ver, b:version) == 0)
  {
    if (ver =~ "^7\.") fixed_ver = "Refer to the vendor.";
    else if (ver =~ "^8\.[01][^0-9]")
      fixed_ver = "Refer to the vendor.";
    else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.53)"))
      fixed_ver = "8.2(5.53) / 8.2(5.55)";
    else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.43)"))
      fixed_ver = "8.3(2.43)";
    else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.25)"))
      fixed_ver = "8.4(7.25) / 8.4(7.26) / 8.4(7.170)";
    else if (ver =~ "^8\.5[^0-9]")
      fixed_ver = "Refer to vendor.";
    else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.16)"))
      fixed_ver = "8.6(1.16)";
    else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.27)"))
      fixed_ver = "9.0(4.27) / 9.0(4.29)";
    else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.101)"))
      fixed_ver = "9.1(5.101) / 9.1(6)";
    else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.1)"))
      fixed_ver = "9.2(3.1) / 9.2(3.3)";
    else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(2.1)"))
      fixed_ver = "9.3(2.1) / 9.3(2.2) / 9.3(2.99) / 9.3(2.201)";
    break;
  }
}

if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(port:0);
