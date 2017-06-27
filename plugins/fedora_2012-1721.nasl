#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1721.
#

include("compat.inc");

if (description)
{
  script_id(58080);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/20 22:34:52 $");

  script_bugtraq_id(51194, 51467, 52009, 52011, 52012, 52013, 52014, 52017, 52018);
  script_xref(name:"FEDORA", value:"2012-1721");

  script_name(english:"Fedora 15 : java-1.6.0-openjdk-1.6.0.0-63.1.10.6.fc15 (2012-1721)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update contains the following security fixes :

    - S7082299, CVE-2011-3571: Fix in AtomicReferenceArray

	- S7088367, CVE-2011-3563: Fix issues in java sound

	- S7110683, CVE-2012-0502: Issues with some
	  KeyboardFocusManager method

	- S7110687, CVE-2012-0503: Issues with TimeZone
	  class

	- S7110700, CVE-2012-0505: Enhance exception
	  throwing mechanism in ObjectStreamClass

    - S7110704, CVE-2012-0506: Issues with some method in
      corba

	- S7112642, CVE-2012-0497: Incorrect checking for
	  graphics rendering object

    - S7118283, CVE-2012-0501: Better input parameter
      checking in zip file processing

    - S7126960, CVE-2011-5035: (httpserver) Add property to
      limit number of request headers to the HTTP Server

This release also contains the following additional fix :

    - PR865: Patching fails with
      patches/ecj/jaxws-getdtdtype.patch

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f7a8fbd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"java-1.6.0-openjdk-1.6.0.0-63.1.10.6.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk");
}
