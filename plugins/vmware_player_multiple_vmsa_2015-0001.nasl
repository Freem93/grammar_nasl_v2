#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81185);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/21 04:38:56 $");

  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044");
  script_bugtraq_id(72336, 72337, 72338);
  script_osvdb_id(117669, 117670, 117671);
  script_xref(name:"VMSA", value:"2015-0001");

  script_name(english:"VMware Player 6.x < 6.0.5 Multiple Vulnerabilities (VMSA-2015-0001) (Windows)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote host is version
6.x prior to 6.0.5. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists that allows a local attacker
    to escalate privileges or cause a denial of service
    via an arbitrary write to a file. (CVE-2014-8370)

  - An input validation error exists in the Host Guest File
    System (HGFS) that allows a local attacker to cause a
    denial of service of the guest operating system.
    (CVE-2015-1043)

  - An input validation error exists in the VMware
    Authorization process (vmware-authd) that allows a
    remote attacker to cause a denial of service of the host
    operating system. (CVE-2015-1044)");
  # http://lists.vmware.com/pipermail/security-announce/2015/000286.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bded33c");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Player 6.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Player/Path", "VMware/Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit("VMware/Player/Version");
path = get_kb_item_or_exit("VMware/Player/Path");
fix = "6.0.5";

if (version =~ "^6\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
