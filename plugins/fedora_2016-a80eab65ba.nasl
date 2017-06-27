#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-a80eab65ba.
#

include("compat.inc");

if (description)
{
  script_id(92277);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 17:03:06 $");

  script_cve_id("CVE-2016-4002", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-4964", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338");
  script_xref(name:"FEDORA", value:"2016-a80eab65ba");

  script_name(english:"Fedora 24 : 2:qemu (2016-a80eab65ba)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2016-4002: net: buffer overflow in MIPSnet (bz
    #1326083)

  - CVE-2016-4952 scsi: pvscsi: out-of-bounds access issue

  - CVE-2016-4964: scsi: mptsas infinite loop (bz #1339157)

  - CVE-2016-5106: scsi: megasas: out-of-bounds write (bz
    #1339581)

  - CVE-2016-5105: scsi: megasas: stack information leakage
    (bz #1339585)

  - CVE-2016-5107: scsi: megasas: out-of-bounds read (bz
    #1339573)

  - CVE-2016-4454: display: vmsvga: out-of-bounds read (bz
    #1340740)

  - CVE-2016-4453: display: vmsvga: infinite loop (bz
    #1340744)

  - CVE-2016-5126: block: iscsi: buffer overflow (bz
    #1340925)

  - CVE-2016-5238: scsi: esp: OOB write (bz #1341932)

  - CVE-2016-5338: scsi: esp: OOB r/w access (bz #1343325)

  - CVE-2016-5337: scsi: megasas: information leakage (bz
    #1343910)

  - Fix crash with -nodefaults -sdl (bz #1340931)

  - Add deps on edk2-ovmf and edk2-aarch64

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-a80eab65ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 2:qemu package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"qemu-2.6.0-4.fc24", epoch:"2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "2:qemu");
}
