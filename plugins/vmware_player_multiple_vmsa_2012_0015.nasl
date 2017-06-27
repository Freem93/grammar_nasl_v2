#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63076);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/01/26 03:37:38 $");

  script_cve_id("CVE-2012-5458", "CVE-2012-5459");
  script_bugtraq_id(56469, 56470);
  script_osvdb_id(87118, 87119);
  script_xref(name:"VMSA", value:"2012-0015");

  script_name(english:"VMware Player 4.x < 4.0.5 Multiple Vulnerabilities (VMSA-2012-0015)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Player 4.x install detected on the remote host is earlier
than 4.0.5 and is, therefore, potentially affected by the following
vulnerabilities :

  - Certain processes, when created, have weak security
    permissions assigned.  It is possible to commandeer
    these process threads, which could result in elevation
    of privileges in the context of the host. (CVE-2012-5458)

  - A DLL binary planning vulnerability exists that could be
    exploited by an attacker to execute arbitrary code on
    the remote host. (CVE-2012-5459)");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0015.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000193.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Player 4.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


version = get_kb_item_or_exit("VMware/Player/Version");
path = get_kb_item_or_exit("VMware/Player/Path");

if (version !~ '^4\\.0') exit(0, "The VMware Player install under "+path+" is "+version+", not 4.x.");

fixed_version = '4.0.5';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
