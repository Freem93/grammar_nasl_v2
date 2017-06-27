#TRUSTED 05ab806f2a3da1ecbe89390002f14f72b326941bd4b16ed7e04c75bf3e4c387eef1575aaf27619c049e5e88c26c385817452fa42887ae664bb2f8f4a4201c6f11b26fd6611791d685d4ffc8ea819dcd0fdf01d6a3aa7de8f26266a2db1b79695122ac43b60161ef9f56fae78e2c678fca23712391263432723d6cb2b3ab03e475c9949f2681139224ab69ee0929a377ace347ea7bf97019f9ee9050136685561132e7a655d41710b60fa232f8aba06289bb3b7ac1f6c6df2974225eed126fca811f13b53e5909f8c9cda593fa636eeacb5dd025dc1f210bee6448ed2011cf3bf2e44b4c0437af07d21e5e85aa5e15ef81daab36583231111a4a8fc2f591b4929f05096280bef7d7e88abbcbf58ecd89e8aa442bb4acbf70d1e0dcd08d5eef82a1ea617c89535946ed1baf343bdcdcba4cd3e24ac3d6e8764e51304a55d25b0b5a1825804c9ba6bf857fefd051e45c03345c3a005404840518a39f576ac795cd9a4499d6e0e1ae5ed832d9eedc4b5aec6284390943e2a2e6d71c9ee7221283051eb766b4de972f9b2f12cad5cb2bd52cf276a755011911390119f7ad96a666e0f941cb41cebb3971dda64d319b573690924f39d5eba999fedb0f650446712dd2ff3f394c9460f8e71239bd834b9ce4f73d95aec42496dca992b7ae1f356e1fe4c19c8e1bbe0612d67e031e9e941ad3b400279584456295f65262628ec490ed0b5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96660);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/21");

  script_cve_id("CVE-2017-2302");
  script_bugtraq_id(95394);
  script_osvdb_id(149996);
  script_xref(name:"JSA", value:"JSA10771");

  script_name(english:"Juniper Junos rpd BGP add-path DoS (JSA10771)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the routing process daemon (rpd) due to improper
handling of BGP packets. An unauthenticated, remote attacker can
exploit this issue, by sending specially crafted BGP packets, to
cause the rdp daemon to crash and restart.

Note that this vulnerability only affects devices configured with the
BGP add-path feature enabled with the 'send' option or with both the
'send' and 'receive' options.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10771");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10771.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D55';
fixes['12.1X47'] = '12.1X47-D45';
fixes['12.3']    = '12.3R13';
fixes['12.3X48'] = '12.3X48-D35';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R6';
fixes['15.1F']   = '15.1F2';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  lines = split(buf, sep:'\n', keep:FALSE);
 
  # Parse BGP groups that have 'add-path' feature is enabled with 'send' option 
  pattern = "^set.* protocols bgp group (\S+) .* add-path.* send";
  groups  = make_list();   

  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:pattern);
    if (matches)
    {
      if (junos_check_config(buf:buf, pattern:matches[0]))
        groups = make_list(groups, matches[1]);
    }
  }
  if (empty(groups))
    audit(AUDIT_HOST_NOT, "affected because the BGP 'add-path' feature is not enabled with the 'send' option");

  # Parse local_address from parsed BGP group
  local_addresses = make_list();
  foreach line (lines)
  {
    foreach group (list_uniq(groups)) 
    {
      pattern = "^set.* protocols bgp group " + group + " local-address (\S+)"; 
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        matches = pregmatch(string:line, pattern:pattern);
        if (matches)
          local_addresses = make_list(local_addresses, matches[1]);
      }  
    }
  }
  if (empty(local_addresses))
    audit(AUDIT_HOST_NOT, "affected because no interface with BGP has the 'add-path' feature with the 'send' option enabled");

  # Check if parsed interfaces have the vulnerable BGP configuration
  foreach local_address (list_uniq(local_addresses))
  {
    pattern = "^set interfaces .* address " + local_address;
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override)
    audit(AUDIT_HOST_NOT, "affected because no interface with BGP has the 'add-path' feature with the 'send' option enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
