#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71052);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2013-5972");
  script_bugtraq_id(63739);
  script_osvdb_id(99788);
  script_xref(name:"VMSA", value:"2013-0013");

  script_name(english:"VMware Player 5.x < 5.0.3 Host Privilege Escalation (VMSA-2013-0013)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains software with a known, local privilege
escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of VMware Player 5.x running on Linux is earlier
than 5.0.3.  It therefore reportedly contains a vulnerability in its
handling of shared libraries.  This issue may allow a local, malicious
user to escalate privileges to root on the host."
  );
  script_set_attribute(attribute:"solution", value:"Update to VMware Player 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
fixed = '5.0.3';


# 5.x < 5.0.3
if (
  ver_compare(ver:version, fix:'5.0.0', strict:FALSE) >= 0 &&
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
