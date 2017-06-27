#TRUSTED 995d6f64107879983203472bd339cb4e746f95c8de646ec696621fc3164a1a5bac6ff44ab7e12c13a0b60f4e9947cd66029c448afbf7ea86af291b5831b85e4cb3df40340ca1914461e241ab215954ddbda54537aa376170f73d9613d9b456619a1433241f6e23c4a17b52590416b62b1b2c37073d48de9a85f1444d99c51e8c6d2a9a64c17842d5abbdb7b6051d8419189ea2aed671c2f01afbb943da4d4a7e293295313c5d4fa6e8ba77c34f222e45f16b810687aa9b6aefc36a95d1a79c946682fdb30307d271d5a4b967593840cd7fffcfb0be82ea038d6ea08ada7aef7bee81327f6177807df75f996cde982b52dbf55ba5b1314b30441f288fb4393d60b1342a3cef34be00364cf8ed9080f08cda607526c72e643039dbe778e7b9f2531e711bc2ad2676e9380240d28da3e299dcf811358d511c56546a8457536366fb6205d06644b3d65ffc6b4fe6869fcd411eab6480b9d3baba183f86a83b871bc124ec294b8f5ec88e7c5400449f5fc65fd270fd4c771a43627415fd94861617e937319f9ce8984ace3d64f4518d9c28f49d6e9a9c1c494f875586429d0a9603f4ad7a7964ee545cad850ba3e80e36405efed8d2e145ce3bcfcdb2fbd5c1d02cc5f5c8af292a4f17f49554f04dcb9d6cf01834b61b2fbcd5a8e1b62d92c91982c23ed909dd8b3e2625ee61bcbab3758612afbecef14966cd6ae7db4c6931883469
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96658);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/21");

  script_cve_id("CVE-2017-2300");
  script_bugtraq_id(95400);
  script_osvdb_id(149993);
  script_xref(name:"JSA", value:"JSA10768");

  script_name(english:"Juniper Junos SRX Series Gateway Chassis Cluster flowd Multicast Session DoS (JSA10768)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos SRX series device is affected by a denial of
service vulnerability in the flow daemon (flowd) when handling
multicast session synchronization. An unauthenticated, adjacent
attacker can exploit this issue, by sending specially crafted
multicast packets, to cause the flowd daemon to crash and restart.

Note that this vulnerability only occurs in chassis cluster
configurations that process transit multicast traffic. Transit
multicast traffic is processed on an SRX services gateway by enabling
PIM in normal Flow Mode, or via security policies permitting transit
multicast traffic in L2/Transparent Mode.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version, model, and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10768");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10768.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D65';
fixes['12.3X48'] = '12.3X48-D40';
fixes['15.1X49'] = '15.1X49-D60';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Check if PIM is disabled globally or family or per-interface
  # Global
  if (preg(string:buf, pattern:"^set protocols pim disable$", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because PIM is disabled globally');

  lines = split(buf, sep:'\n', keep:FALSE);

  # Families
  patterns = make_list(
    "^set protocols pim family inet(\s|$)",
    "^set protocols pim family inet6",
    "^set protocols pim rp local family inet(\s|$)",
    "^set protocols pim rp local family inet6"
  );

  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }

  # Per-interface
  if (override)
  {
    nics  = make_list();

    #  Grab NICs with PIM activated
    foreach line (lines)
    {
      pattern = "^set protocols pim interface (\S+)";
    
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        matches = pregmatch(string:line, pattern:pattern);
        if (matches)
          nics = make_list(nics, matches[1]);
      }
    }

    #  Check if any of the NICs have PIM enabled
    foreach nic (list_uniq(nics))
    {
      pattern = "^set protocols pim interface " + nic;
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        override = FALSE;
        break;
      }
    }
  }
  if (override) audit(AUDIT_HOST_NOT, 'affected because PIM is not enabled on any interfaces');
}
  
buf = junos_command_kb_item(cmd:"show chassis cluster statistics");
if (buf)
{
  if (preg(string:buf, pattern:"Chassis cluster is not enabled", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because the chassis cluster is not enabled");
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
