#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59818);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/07/03 12:55:10 $");

  script_cve_id("CVE-2012-2449", "CVE-2012-3288");
  script_bugtraq_id(53996);
  script_osvdb_id(81694, 82979);
  script_xref(name:"VMSA", value:"2012-0009");
  script_xref(name:"VMSA", value:"2012-0011");

  script_name(english:"VMware Fusion 4.x < 4.1.3 (VMSA-2012-0009, VMSA-2012-0011)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion 4.x installed on the Mac OS X host is
earlier than 4.1.3, and is therefore reportedly affected by the
following vulnerabilities :

  - Due to a flaw in the virtual floppy configuration it is
    possible to perform an out-of-bounds memory write. This
    vulnerability may allow a guest user to crash the VMX
    process or potentially execute code on the host. As a
    workaround, remove the virtual floppy drive from the
    list of virtual IO devices. The VMware hardening guides
    recommend removing unused virtual IO devices in general.
    Additionally, do not allow untrusted root users in your
    virtual machines. Root or Administrator level
    permissions are required to exploit this issue.
    (CVE-2012-2449)

  - A memory corruption error exists related to the
    handling of 'Checkpoint' files that can allow arbitrary
    code execution. (CVE-2012-3288)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0011.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb5b232d");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 4.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
fixed_version = "4.1.3";

if (version =~ '^4\\.' && ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Fusion", version);
