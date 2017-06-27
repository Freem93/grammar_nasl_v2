#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85707);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/01 13:24:51 $");

  script_cve_id("CVE-2014-0875");
  script_bugtraq_id(68398);
  script_osvdb_id(108725);

  script_name(english:"IBM Storwize V7000 Unified ACL Security Bypass");
  script_summary(english:"Checks for vulnerable Storwize models.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an ACL security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote IBM Storwize device is affected by an ACL security bypass
vulnerability due to a race condition in the Active Cloud Engine (ACE)
component caused by an error in NFS packet retransmission in response
to noisy or slow responding networks. An authenticated, remote
attacker can exploit this to bypass intended ACL restrictions in
opportunistic circumstances by leveraging incorrect ACL
synchronization over an unreliable NFS connection that requires
retransmissions.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004738");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Storwize version 1.5.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_unified_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_unified_v7000_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_storwize_detect.nbin");
  script_require_ports("Host/IBM/Storwize/version", "Host/IBM/Storwize/machine_major", "Host/IBM/Storwize/display_name");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/Storwize/version");
machine_major = get_kb_item_or_exit("Host/IBM/Storwize/machine_major");
display_name = get_kb_item_or_exit("Host/IBM/Storwize/display_name");

fix = "1.5.0.0";

# audit out if it isn't an affected device
if (
  machine_major != "2073" # V7000 Unified
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == "Unknown" || version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, "IBM Storwize");

if (version !~ "^[0-9.]+$")
  audit(AUDIT_VER_FORMAT, version);

if (
  version !~ "^1\.(3|4\.[0-3])\." ||
  ver_compare(ver:version, fix:fix, strict:FALSE) >= 0
) audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

if (report_verbosity > 0)
{
  report =
    '\n  Name              : ' + display_name +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:0, extra:report);
}
else security_note(port:0);
