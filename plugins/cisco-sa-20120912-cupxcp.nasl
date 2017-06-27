#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69425);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2012-3935");
  script_bugtraq_id(55514);
  script_osvdb_id(85421);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu32832");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120912-cupxcp");

  script_name(english:"Cisco Unified Presence Server DoS (cisco-sa-20120912-cupxcp)");
  script_summary(english:"Checks CUPS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Unified
Presence Server installed on the remote host has a denial of service
vulnerability.  An unauthenticated, remote attacker could exploit this
by sending a specially crafted XMPP stream header.  This could cause
existing clients to disconnect, and prevent new clients from
connecting."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120912-cupxcp
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?6ecbd77f");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco Unified Presence Server 8.6(3) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date",value:"2013/08/16");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:unified_presence_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UCOS/Cisco Unified Presence/version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

display_version = get_kb_item_or_exit('Host/UCOS/Cisco Unified Presence/version');
match = eregmatch(string:display_version, pattern:'^([0-9.]+(?:-[0-9]+)?)($|[^0-9])');
if (isnull(match)) # this should not happen
  audit(AUDIT_FN_FAIL, 'eregmatch');
else
  version = match[1];

version = str_replace(string:version, find:"-", replace:".");

# the advisory says All versions prior to 8.6(3) are affected
if (ver_compare(ver:version, fix:'8.6.3', strict:FALSE) < 0)
  fix = '8.6.3';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'CUPS', display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
