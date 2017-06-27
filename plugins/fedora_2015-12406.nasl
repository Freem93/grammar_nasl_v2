#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-12406.
#

include("compat.inc");

if (description)
{
  script_id(85549);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/19 22:57:25 $");

  script_cve_id("CVE-2012-2150");
  script_xref(name:"FEDORA", value:"2015-12406");

  script_name(english:"Fedora 21 : xfsprogs-3.2.2-2.fc21 (2015-12406)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gabriel Vlasiu reported that xfs_metadump, part of the xfsprogs suite
of tools for the XFS filesystem, did not properly obfuscate data.
xfs_metadump properly obfuscates active metadata, but the rest of the
space within that fs block comes through in the clear. This could lead
to exposure of stale disk data via the produced metadump image.

The expectation of xfs_metadump is to obfuscate all but the shortest
names in the metadata, as noted in the manpage :

By default, xfs_metadump obfuscates most file (regular file, directory
and symbolic link) names and extended attribute names to allow the
dumps to be sent without revealing confidential information. Extended
attribute values are zeroed and no data is copied. The only exceptions
are file or attribute names that are 4 or less characters in length.
Also file names that span extents (this can only occur with the
mkfs.xfs(8) options where -n size > -b size) are not obfuscated. Names
between 5 and 8 characters in length inclusively are partially
obfuscated.

While the xfs_metadump tool can be run by unprivileged users, it
requires appropriate permissions to access block devices (such as
root) where the sensitive data might be dumped. An unprivileged user,
without access to the block device, could not use this flaw to obtain
sensitive data they would not otherwise have permission to access.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=817696"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/164189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da675ab8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xfsprogs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xfsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"xfsprogs-3.2.2-2.fc21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xfsprogs");
}
