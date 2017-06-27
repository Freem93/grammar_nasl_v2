#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0668 and 
# CentOS Errata and Security Advisory 2013:0668 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65644);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/06/29 00:03:04 $");

  script_cve_id("CVE-2012-2677");
  script_xref(name:"RHSA", value:"2013:0668");

  script_name(english:"CentOS 5 / 6 : boost (CESA-2013:0668)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated boost packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The boost packages provide free, peer-reviewed, portable C++ source
libraries with emphasis on libraries which work well with the C++
Standard Library.

A flaw was found in the way the ordered_malloc() routine in Boost
sanitized the 'next_size' and 'max_size' parameters when allocating
memory. If an application used the Boost C++ libraries for memory
allocation, and performed memory allocation based on user-supplied
input, an attacker could use this flaw to crash the application or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-2677)

All users of boost are advised to upgrade to these updated packages,
which contain a backported patch to fix this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?136408c2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aed886a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected boost packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-date-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-graph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-graph-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-graph-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-iostreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-mpich2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-mpich2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-openmpi-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-program-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-signals");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:boost-wave");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"boost-1.33.1-16.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"boost-devel-1.33.1-16.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"boost-doc-1.33.1-16.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"boost-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-date-time-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-doc-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-filesystem-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-graph-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-graph-mpich2-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-graph-openmpi-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-iostreams-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-math-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-mpich2-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-mpich2-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-mpich2-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-openmpi-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-openmpi-devel-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-openmpi-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-program-options-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-python-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-regex-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-serialization-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-signals-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-static-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-system-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-test-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-thread-1.41.0-15.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"boost-wave-1.41.0-15.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
