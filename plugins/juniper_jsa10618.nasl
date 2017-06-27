#TRUSTED 3c5ee0dabe6e9085592f0c66a0ffda3f134d358959b515927574cf4bcdd03bce8beacc287db82f6cd8d93e3ea813402051bfeff0d9f6b0d8a9a6ba1ff2a75a42366e910c793702211b819a4aa5e18b3b521a2698944a8a863627560e9bfe47a959aac67fbcba4764269bcaaa018b7123968d76d5d22fa454dbf8f6b72980565734344405a349b41c1babcd701cb85cbd04c2087c63978473f6a106475aa9330924bcc36ca7c0643fbaf13419afff34432142ba3a9de9447f6f143638d4d41d08bc8634e8c61b431b1ff231f9f831c6db57be4ef39f256f4a6a46cb2f32a11a8e31efb4495f14098416b7ff178ef8afe985de27755caa648ddd444110d995c933f8dbe4e3180215bd934f7d38ec10e5e9af5ad8b9abe0cde732a2a429930824585829fe1a84ac3e219f7c31b09e84887419683c620a40f0c2941796d9c234bf66605e9f8458e1586ff45841a8c6f15d2d17597c75131bae3237e37091b5070d8baf6b83e7cde9eeb60746496f3ea5b1f879c7ad5c8d362c550c7ede9f32edb79017021f6a8ed0172ce3b60150791620e09072fb8be1cf65a4478f24c07a9d532973ddb5d5ba267aaa57d114ed9a3cb1592a183fb13fefe55ae01b9504c39da12719692e17ed8a5076db8121c6e8661ecfda611edecefae70cb06cb72252ae1e7c82ea7b955669741f958d0e02566a4b635759a71ece44183587bcc4194ecbc0da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73492);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0614");
  script_bugtraq_id(66762);
  script_osvdb_id(105611);
  script_xref(name:"JSA", value:"JSA10618");

  script_name(english:"Juniper Junos Kernel IGMP Flood DoS (JSA10618)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability in the
Junos kernel. A remote attacker can exploit this issue by sending
specially crafted IGMP packets at a very high rate (approximately 1000
packets per second). 

Note that this issue only affects devices with PIM enabled."); 
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10618");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10618.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2014-01-16') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['13.2'] = '13.2R3';
fixes['13.3'] = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if PIM is disabled globally or family or per-interface
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Global
  if (preg(string:buf, pattern:"^set protocols pim disable$", multiline:TRUE))
    audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

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
    lines = split(buf, sep:'\n', keep:FALSE);
    nics  = make_list();

    #  Grab NICs with PIM activated
    foreach line (lines)
    {
      pattern = "^set protocols pim interface (\S+)";
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
        nics = make_list(nics, matches[1]);
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

  if (override) audit(AUDIT_HOST_NOT, 'affected because PIM is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
