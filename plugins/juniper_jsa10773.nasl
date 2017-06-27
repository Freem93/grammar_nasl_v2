#TRUSTED 39db588e1208b418399edc1ef691db20ddfc26bc8790b691d580325137496a6315411fa6022aecb39d38316f596b001e69e2952fef2e780f175bbe980a9d60fd949b1b88062d6eab1aa765369d7a332e9e9748453ed89dda623b58fe77ff27819e781264b965dcce53de3346136eaebe5d09b2d063a5bd6b927f8a46eb26c893c1d8504d420a14aa413d6ef9bd62056e612b8c0549b7911f9f0057497f97145cb6b1b183494678498e963c90a12000b693940d66a88f574dfae82ebcba615e44d4aa3b95be30090726265fc59b49d2b42387ccdf9613fb7c43b75b0059f577557bf45dc7bea02be636d6ed84fe41e0101bd20a381cdf233a9c3303fe6dfd098ef468baba57f5c9ab3a23510b2cb5cd684ba4efb0c4ec002873c4ffa97d6ea02307572f0f7643c3b43c87557fca5203927808ff650a91cef2db7a643ad4b01e48a1945e0616eee5073eeb239d7aa1889b32e24d3136ebf1671b87b89ae802de5a195788ad6f7f880e91b6c1e53fda44028d7677bffb10b8b384736c9d4997c1ba392cc5b33b5f545a2b1b71ae8e242e05614d0b6e3bbc456c36c34b42bc2312ab1090c60ca1857cc0bce0139a632ff98531a638dce08f036548a48c59599130dd66ccf289d42d5b479d177f7bd8e4dd913a10e4418cd2802cbec070bd5e59f6b8c32b58e2bab879df291754d8399df3af2c1760dcbfab0d5b617293f68c603d1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96662);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/21");

  script_cve_id("CVE-2017-2304");
  script_bugtraq_id(95403);
  script_osvdb_id(149992);
  script_xref(name:"JSA", value:"JSA10773");

  script_name(english:"Juniper Junos QFX / EX Series 'Etherleak' Improper Padding Memory Disclosure (JSA10773)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a memory disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos QFX or EX series device is affected by a memory disclosure
vulnerability, known as Etherleak, due to padding Ethernet packets
with data from previous packets instead of padding them with null
bytes. An unauthenticated, adjacent attacker can exploit this issue to
disclose portions of system memory or data from previous packets. This
issue is also often detected as CVE-2003-0001.

Note that Nessus has not tested for this issue but has instead relied
only on the device's self-reported version and model"); 
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10773");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10773.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^QFX(35|36|51|52)00($|[^0-9])" && model !~ "^EX4[36]00($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected QFX or EX device');

fixes = make_array();
fixes['14.1X53'] = '14.1X53-D40';
fixes['15.1X53'] = '15.1X53-D40';
fixes['15.1R']   = '15.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_NOTE);
