#TRUSTED 36a4500ddf1cfef1147275d3b15e6830b2509673782f45d8962750aceba909afc3b5b7d1b5547c825d70459df9e3454b9ea51b9de70cfe75e93e677fb24723c0474a75e13b659d8c5c283e75bf2bac00d297d94be9101dbb678c469212bebaaaeb644c54c90977472a0671a12a0b943e8360852b429da960fbef4f03765757418838b7e330d2e90fb75fbde62fe4f18e1688f36b156f6d9d5401fcadcda58d4ce48d7498396f64aff7aadc42c505c37dc942a6c41e660f4467f6da717a33f09a391c9f3a0422a74b23df377ad495bb5856f6a71e0dc0053747863f9f375b69d0e4a7eefcffa24c88172c518ebbb342f97a7cc4c2b7422ff3ec87acc53cb36b8bdefc043ab504348d571e53595e8d3ad65bf14caec017791cb9535fd11d3b4e3e689e294e568a6f75cead4369b18b916655c0bd1dc8946d10785c4fb8ef41e9e0aaa25dd368d7ee0eea2464989eec3c13a388d51a22a0335e841f84840784eac2ae9afce7e8be9ed37a5d69c7d09336a70c3ea4802af2df9e1f5f8bef2016c771673bb722f777d748ae9575d2da6d242a59fb424165890e24e0240659fc012bf5b58121ff834e5d53cdb0076d2f5c3282d6741bf596ce1de00ca328efc09985c1c0f179b2a58a97f6f14b30e71f8290016c245f6e1fbec254455039fc0a404f2a9a762e226c48612b306cec3e7154dd6f274d652244761f3eb25ec00c9a80bcb3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73687);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"JSA", value:"JSA10623");

  script_name(english:"Juniper Junos OpenSSL Heartbeat Information Disclosure (JSA10623) (Heartbleed)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by an information disclosure vulnerability. An
out-of-bounds read error, known as Heartbleed, exists in the TLS/DTLS
implementation due to improper handling of TLS heartbeat extension
packets. A remote attacker, using crafted packets, can trigger a
buffer over-read, resulting in the disclosure of up to 64KB of process
memory, which contains sensitive information such as primary key
material, secondary key material, and other protected content.

Note that this issue only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10623");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10623.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (check_model(model:model, flags:J_SERIES | SRX_SERIES, exit_on_fail:TRUE))

fixes = make_array();
fixes['13.3'] = '13.3R1.8';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither J-Web nor SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
