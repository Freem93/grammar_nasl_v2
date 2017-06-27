#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87925);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/02 15:47:18 $");

  script_cve_id("CVE-2015-6933");
  script_osvdb_id(132670);
  script_xref(name:"VMSA", value:"2016-0001");

  script_name(english:"VMware Player 7.x < 7.1.2 Shared Folders (HGFS) Guest Privilege Escalation (VMSA-2016-0001) (Linux)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by a guest privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote host is version
7.x prior to 7.1.2. It is, therefore, affected by a guest privilege escalation
vulnerability in the Shared Folders (HGFS) feature due to improper
validation of user-supplied input. A local attacker can exploit this
to corrupt memory, resulting in an elevation of privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player 7.1.2 or later.

Note that VMware Tools in any Windows-based guests that use the Shared
Folders (HGFS) feature must also be updated to completely mitigate the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
fixed = '7.1.2';

# 7.x < 7.1.2
if (
  ver_compare(ver:version, fix:'7.0.0', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
