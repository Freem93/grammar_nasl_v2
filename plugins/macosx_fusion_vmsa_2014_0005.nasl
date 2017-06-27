#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74263);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2014-3793");
  script_bugtraq_id(67737);
  script_osvdb_id(107561);
  script_xref(name:"VMSA", value:"2014-0005");

  script_name(english:"VMware Fusion 6.x < 6.0.3 Windows 8.1 Guest Privilege Escalation (VMSA-2014-0005)");
  script_summary(english:"Checks Fusion version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote Mac OS X host is
version 6.x prior to 6.0.3. It is, therefore, reportedly affected by a
privilege escalation vulnerability.

A kernel NULL dereference flaw exists in VMware tools on Windows 8.1
guest hosts. An attacker could escalate his privileges on the guest
host.

Note that successful exploitation of the vulnerability does not allow
privilege escalation from the guest host to the host system.");
  # https://www.vmware.com/support/fusion6/doc/fusion-603-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd08e50e");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 6.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
path = get_kb_item_or_exit("MacOSX/Fusion/Path");

fixed_version = '6.0.3';
if (
  version =~ "^6\." &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
