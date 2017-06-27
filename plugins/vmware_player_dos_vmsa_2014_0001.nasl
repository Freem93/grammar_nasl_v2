#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72038);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2014-1208");
  script_bugtraq_id(64994);
  script_osvdb_id(102197);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware Player 5.x < 5.0.1 VMX Process DoS (VMSA-2014-0001)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Player 5.x running on the remote
Windows host is a version prior to 5.0.1.  It is, therefore, reportedly
affected by a denial of service vulnerability due to an issue with
handling invalid ports that could allow a guest user to crash the VMX
process.");
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
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

fixed = '5.0.1';

if (
  version =~ "^5\." &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
