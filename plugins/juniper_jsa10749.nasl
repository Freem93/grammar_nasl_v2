#TRUSTED a38e78d0fc765a549776ab1351dfd823ca10a72273f673b3fad789b966fbcc0cf47e0230f0539d4fa3ed4b2090b62acd055553ebeb9d515c21895b634eb092047fb1c59d316c2737c50071758a537c6febeb742b7925c046641f478fd60fdbf580f15e21281a64c6f36fc43802c627174ec7f4c163e0a388711c58eeb0e9d56afec08fd0dd2d8f0a932b951a16737378837bf548bdf502a0a2ac4c79d5214d3f89cb61828bb3b083d515ec49bc2b4d31480dff28e3e264b71097373b5f3a0bc476005833b96c919843b03ac84258688abc9f2cca24b2c033eb9042edc197af761ef8d71dce61cfb590cf424be7ad96518d5a5afd143794b8f622e48e5db002c2b16553347e69c057613fdd1cd2d261757d8739978da8dc27a5f262ce62f7323ed7b0d3fa2b829928274f3109b186b5298c6666bb1ee1776bd9a4623a208e8d50e201534389d9245add84c245ea93658aa6d6e26a658b7bb804829fc7936229de86e0a69a4b132c805b296d6cfce856600bdf0fdc89976274bdbeac6dfffd2e2ee9a8cb68147ee996ec9030b63ded020014547eadabcfb15ba6194b7e4fbc6ec82ff37acb9db6467af781f1b749c0666429b43efa27e40c8a51608c2b41b2892b71052cabbf7ab4703ac79e237bf2e125c4ee32d577e5bafd152726ea384907f6e9d0c274d010a41897749281c5310afa59084daa597a8efd6dcb3877b15aeae2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91762);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/22");

  script_cve_id("CVE-2016-1409");
  script_osvdb_id(139535, 139536, 139537);
  script_xref(name:"JSA", value:"JSA10749");

  script_name(english:"Juniper Junos IPv6 Neighbor Discovery (ND) Traffic Handling Multiple Vulnerabilities (JSA10749)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple vulnerabilities :

  - A flaw exists due to improper handling of malformed IPv6
    ND packets. An unauthenticated, remote attacker can
    exploit this, via specially crafted ND packets, to cause
    the device to stop processing IPv6 traffic, resulting in
    a denial of service condition. (VulnDB 139535)

  - A flaw exists that is triggered when handling QFX5100
    exceptions. An unauthenticated, remote attacker can
    exploit this to transition IPv6 ND traffic to the
    routing engine, resulting in a partial denial of service
    condition. (VulnDB 139536)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to cause improper
    forwarding of IPv6 ND traffic in violation of RFC4861.
    (VulnDB 139537)

Note that Nessus has not tested for these issues but has instead
relied only on the device's self-reported model and current
configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10749");
  script_set_attribute(attribute:"solution", value:
"No fix is currently available. Refer to the vendor advisory for an
example firewall filter workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# Note that only MX, PTX, and QFX have been confirmed to experience this behavior.
check_model(
  model:model,
  flags:MX_SERIES | PTX_SERIES | QFX_SERIES,
  exit_on_fail:TRUE
);

# Check if IPv6 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces .* family inet6 ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  override = FALSE;
}

fix = "Refer to the vendor for a fix.";

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
