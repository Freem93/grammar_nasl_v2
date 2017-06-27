#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61257);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2006-1168", "CVE-2011-2716");

  script_name(english:"Scientific Linux Security Update : busybox on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"BusyBox provides a single binary that includes versions of a large
number of system commands, including a shell. This can be very useful
for recovering from certain types of system failures, particularly
those involving broken shared libraries.

A buffer underflow flaw was found in the way the uncompress utility of
BusyBox expanded certain archive files compressed using Lempel-Ziv
compression. If a user were tricked into expanding a specially crafted
archive file with uncompress, it could cause BusyBox to crash or,
potentially, execute arbitrary code with the privileges of the user
running BusyBox. (CVE-2006-1168)

The BusyBox DHCP client, udhcpc, did not sufficiently sanitize certain
options provided in DHCP server replies, such as the client hostname.
A malicious DHCP server could send such an option with a specially
crafted value to a DHCP client. If this option's value was saved on
the client system, and then later insecurely evaluated by a process
that assumes the option is trusted, it could lead to arbitrary code
execution with the privileges of that process. Note: udhcpc is not
used on Scientific Linux by default, and no DHCP client script is
provided with the busybox packages. (CVE-2011-2716)

This update also fixes the following bugs :

  - Prior to this update, the cp command wrongly returned
    the exit code 0 to indicate success if a device ran out
    of space while attempting to copy files of more than 4
    gigabytes. This update modifies BusyBox, so that in such
    situations, the exit code 1 is returned. Now, the cp
    command shows correctly whether a process failed.

  - Prior to this update, the findfs command failed to check
    all existing block devices on a system with thousands of
    block device nodes in '/dev/'. This update modifies
    BusyBox so that findfs checks all block devices even in
    this case.

All users of busybox are advised to upgrade to these updated packages,
which correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3293
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cc2b825"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected busybox and / or busybox-anaconda packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"busybox-1.2.0-13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"busybox-anaconda-1.2.0-13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
