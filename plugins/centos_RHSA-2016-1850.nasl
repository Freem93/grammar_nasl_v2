#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1850 and 
# CentOS Errata and Security Advisory 2016:1850 respectively.
#

include("compat.inc");

if (description)
{
  script_id(93542);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8932", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-7166");
  script_osvdb_id(118253, 118255, 134899, 140116, 140356, 140480, 142331);
  script_xref(name:"RHSA", value:"2016:1850");

  script_name(english:"CentOS 6 : libarchive (CESA-2016:1850)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libarchive is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libarchive programming library can create and read several
different streaming archive formats, including GNU tar, cpio and ISO
9660 CD-ROM images. Libarchive is used notably in the bsdtar utility,
scripting language bindings such as python-libarchive, and several
popular desktop file managers.

Security Fix(es) :

* A flaw was found in the way libarchive handled hardlink archive
entries of non-zero size. Combined with flaws in libarchive's file
system sandboxing, this issue could cause an application using
libarchive to overwrite arbitrary files with arbitrary data from the
archive. (CVE-2016-5418)

* Multiple out-of-bounds read flaws were found in libarchive.
Specially crafted AR or MTREE files could cause the application to
read data out of bounds, potentially disclosing a small amount of
application memory, or causing an application crash. (CVE-2015-8920,
CVE-2015-8921)

* A denial of service vulnerability was found in libarchive's handling
of GZIP streams. A crafted GZIP file could cause libarchive to
allocate an excessive amount of memory, eventually leading to a crash.
(CVE-2016-7166)

* A denial of service vulnerability was found in libarchive. A
specially crafted CPIO archive containing a symbolic link to a large
target path could cause memory allocation to fail, causing an
application using libarchive that attempted to view or extract such
archive to crash. (CVE-2016-4809)

* Multiple instances of undefined behavior due to arithmetic overflow
were found in libarchive. Specially crafted Compress streams or
ISO9660 volumes could potentially cause the application to fail to
read the archive, or to crash. (CVE-2015-8932, CVE-2016-5844)

Red Hat would like to thank Insomnia Security for reporting
CVE-2016-5418."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-September/022067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0e5dbfd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libarchive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libarchive-2.8.3-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libarchive-devel-2.8.3-7.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
