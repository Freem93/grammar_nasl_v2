#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74264);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/10/21 11:02:26 $");

  script_cve_id("CVE-2014-3793");
  script_bugtraq_id(67737);
  script_osvdb_id(107561);
  script_xref(name:"VMSA", value:"2014-0005");

  script_name(english:"VMware Player 6.x < 6.0.2 Windows 8.1 Guest Privilege Escalation (VMSA-2014-0005) (Linux)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Player 6.x running on the remote Linux
host is prior to 6.0.2. It is, therefore, reportedly affected by a
privilege escalation vulnerability.

A kernel NULL dereference flaw exists in VMware tools on Windows 8.1
guest hosts. An attacker could escalate his privileges on the guest
host.

Note that successful exploitation of the vulnerability does not allow
privilege escalation from the guest host to the host system.");
  # https://www.vmware.com/support/player60/doc/player-602-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7df547df");

  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Player 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("Host/VMware Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Player/Version");
fixed = '6.0.2';

# 6.x < 6.0.2
if (
  ver_compare(ver:version, fix:'6.0.0', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
