#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54974);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/02/01 20:08:08 $");

  script_cve_id("CVE-2011-1787", "CVE-2011-2145", "CVE-2011-2146", "CVE-2011-3868");
  script_bugtraq_id(48098, 49942);
  script_osvdb_id(73240, 73241, 73242, 76060);
  script_xref(name:"VMSA", value:"2011-0009");
  script_xref(name:"VMSA", value:"2011-0011");

  script_name(english:"VMware Fusion < 3.1.3 (VMSA-2011-0009 / VMSA-2011-0011)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Fusion installed on the Mac OS X host is
earlier than 3.1.3.  As such, it is reportedly affected by the
following three security vulnerabilities :

  - An attacker with access to a Guest operating system can
    determine if a path exists in the Host filesystem and
    whether it's a file or a directory regardless of
    permissions. (CVE-2011-2146)

  - A race condition in mount.vmhgfs may allow an attacker
    with access to a Guest to mount on arbitrary directories
    in the Guest filesystem and escalate their privileges if
    they can control the contents of the mounted directory.
    (CVE-2011-1787)

  - A procedural error allows an attacker with access to a
    Solaris or FreeBSD Guest operating system to gain write 
    access to an arbitrary file in the Guest filesystem.
    (CVE-2011-2145)

  - A buffer overflow in the way UDF file systems are 
    handled could allow for code execution if a specially
    crafted ISO image is used. (CVE-2011-3868)

Note that the first three vulnerabilities only affect non-Windows
guest operating systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2011-0011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000145.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 3.1.3 or later.

In addition to patching, VMware Tools must be updated on all non-
Windows guest VMs in order to completely mitigate certain
vulnerabilities.  Refer to the VMware advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("MacOSX/Fusion/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
fixed_version = "3.1.3";

if (version =~ '^3\\.1' && ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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
else exit(0, "The host is not affected since VMware Fusion "+version+" is installed.");
