#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71231);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/05 21:47:31 $");

  script_cve_id("CVE-2013-3519");
  script_bugtraq_id(64075);
  script_osvdb_id(100514);
  script_xref(name:"VMSA", value:"2013-0014");

  script_name(english:"VMware Player 5.x < 5.0.3 LGTOSYNC.SYS Guest Privilege Escalation (VMSA-2013-0014)");
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
"The installed version of VMware Player 5.x running on Windows is
earlier than 5.0.3.  It therefore reportedly contains a vulnerability in
its handling in the LGTOSYNC.SYS driver.  This issue could allow a
local, malicious user to escalate privileges on 32-bit Guest Operating
Systems running Windows XP. 

Note that by exploiting this issue, a local attacker could elevate his
privileges only on the Guest OS and not on the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0014.html");
  script_set_attribute(attribute:"solution", value:"Update to VMware Player 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

fixed = '5.0.3';
if (
  ver_compare(ver:version, fix:'5.0.0', strict:FALSE) >= 0 &&
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
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
