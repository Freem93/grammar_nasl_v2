#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76346);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/03 00:30:41 $");

  script_cve_id("CVE-2012-3946");
  script_bugtraq_id(68261);
  script_osvdb_id(106274);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty73682");

  script_name(english:"Cisco IOS IPv6 Packet ACL Restriction Bypass");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported IOS version, the remote device is
affected by a security bypass vulnerability.

The flaw is due to the handling of specially crafted IPv6 packets in
an unspecified scenario. A remote attacker, with a specially crafted
request, could bypass the ACL restrictions on the interface.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCty73682/");
  # http://www.cisco.com/c/en/us/td/docs/ios/15_3s/release/notes/15_3s_rel_notes/15_3s_caveats_15_3_2s.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?652d2c01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the bug
details for CSCty73682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "ciscoASR9[0-9]{2}$") audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if ("ASR9" >!< model || "ASR9k" >< model) audit(AUDIT_HOST_NOT, "affected");
}

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

fixed = NULL;

if (version == '15.2(4)S') fixed = '15.2(4)S1.5';
if (version == '15.3(1)S1') fixed = '15.3(2)S';
if (version == '15.3(1)S1e') fixed = '15.3(2)S';
if (version == '15.3(1)S2') fixed = '15.3(2)S';

if (fixed)
{
  if (report_verbosity > 0)
  {
     report = '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed +
              '\n';
     security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'IOS', version);
