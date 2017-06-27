#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72039);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2014-1208");
  script_bugtraq_id(64994);
  script_osvdb_id(102197);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware Player 5.x < 5.0.1 VMX Process DoS (VMSA-2014-0001) (Linux)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Player 5.x running on the remote Linux
host is a version prior to 5.0.1.  It is, therefore, affected by a
denial of service vulnerability due to an issue with handling invalid
ports that could allow a guest user to crash the VMX process.");
  script_set_attribute(attribute:"solution", value:"Update to VMware Player 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

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
fixed = '5.0.1';


# 5.x < 5.0.1
if (
  version =~ "^5\." &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
