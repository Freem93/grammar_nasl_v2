#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81952);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2015-0652");
  script_bugtraq_id(73047);
  script_osvdb_id(119447);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun73192");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150311-vcs");

  script_name(english:"Cisco TelePresence Conductor SDP Media Description Vulnerability");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco TelePresence
Conductor on the remote host contains an vulnerability related to the
Session Description Protocol (SDP) packet handler function. A remote,
unauthenticated attacker, using a crafted SDP packet to trigger a
reload, can exploit this to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCun73192");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150311-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcf7f93e");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.4 later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_conductor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_conductor_detect.nbin");
  script_require_keys("Host/Cisco_TelePresence_Conductor/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod = "Cisco TelePresence Conductor";
version = get_kb_item_or_exit("Host/Cisco_TelePresence_Conductor/Version");

# XC2.4PreAlpha0 is listed as vuln,
# however it is unclear what such a
# version string would look like;
# omitted for now.
if (
  version =~ "^1(\.|$)"        ||
  version =~ "^2\.[0-3](\.|$)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed versions    : 2.4' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
