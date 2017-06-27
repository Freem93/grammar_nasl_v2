#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60838);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-0428", "CVE-2010-0429");

  script_name(english:"Scientific Linux Security Update : qspice on SL5.x x86_64");
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
"It was found that the libspice component of QEMU-KVM on the host did
not validate all pointers provided from a guest system's QXL graphics
card driver. A privileged guest user could use this flaw to cause the
host to dereference an invalid pointer, causing the guest to crash
(denial of service) or, possibly, resulting in the privileged guest
user escalating their privileges on the host. (CVE-2010-0428)

It was found that the libspice component of QEMU-KVM on the host could
be forced to perform certain memory management operations on memory
addresses controlled by a guest. A privileged guest user could use
this flaw to crash the guest (denial of service) or, possibly,
escalate their privileges on the host. (CVE-2010-0429)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=1872
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a22d5457"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected qspice, qspice-libs and / or qspice-libs-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"qspice-0.3.0-54.el5_5.2")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"qspice-libs-0.3.0-54.el5_5.2")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"qspice-libs-devel-0.3.0-54.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
