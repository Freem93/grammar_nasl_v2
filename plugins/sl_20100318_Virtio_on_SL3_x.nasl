#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60751);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_name(english:"Scientific Linux Security Update : Virtio on SL3.x i386/x86_64");
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
"This new package provides signed, para-virtualized block and network
drivers for Scientific Linux 3 as a KVM virtualized guest.

Users may see various warnings during package installation, 
including :

  - Different versions of package are already installed.
    Older versions of the package may cause 'File exists'
    error messages to appear. The package will install
    successfully the error messages just inform the user
    that files for devices exist. This warning can be
    ignored.

  - If the previous installed package was for a different
    kernel (for example, kmod-virtio-smp on hugemem system),
    the installation will fail. Modules cannot be inserted
    and a 'Wrong number of arguments' error message will
    appear. To fix this issue, create nodes manually as
    covered in the README file. This issue can be prevented
    by installing the correct drivers for the kernel
    package."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=3116
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db0cd96d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kmod-virtio, kmod-virtio-hugemem and / or
kmod-virtio-smp packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
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
if (rpm_check(release:"SL3", reference:"kmod-virtio-0.1-17.el3")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kmod-virtio-hugemem-0.1-17.el3")) flag++;
if (rpm_check(release:"SL3", reference:"kmod-virtio-smp-0.1-17.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
