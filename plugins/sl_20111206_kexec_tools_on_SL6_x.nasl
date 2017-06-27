#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61189);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/19 11:43:47 $");

  script_cve_id("CVE-2011-3588");

  script_name(english:"Scientific Linux Security Update : kexec-tools on SL6.x i386/x86_64");
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
"Kexec allows for booting a Linux kernel from the context of an already
running kernel.

Kdump used the SSH (Secure Shell) 'StrictHostKeyChecking=no' option
when dumping to SSH targets, causing the target kdump server's SSH
host key not to be checked. This could make it easier for a
man-in-the-middle attacker on the local network to impersonate the
kdump SSH target server and possibly gain access to sensitive
information in the vmcore dumps. (CVE-2011-3588)

mkdumprd created initrd files with world-readable permissions. A local
user could possibly use this flaw to gain access to sensitive
information, such as the private SSH key used to authenticate to a
remote server when kdump was configured to dump to an SSH target.
(CVE-2011-3589)

mkdumprd included unneeded sensitive files (such as all files from the
'/root/.ssh/' directory and the host's private SSH keys) in the
resulting initrd. This could lead to an information leak when initrd
files were previously created with world-readable permissions. Note:
With this update, only the SSH client configuration, known hosts
files, and the SSH key configured via the newly introduced sshkey
option in '/etc/kdump.conf' are included in the initrd. The default is
the key generated when running the 'service kdump propagate' command,
'/root/.ssh/kdump_id_rsa'. (CVE-2011-3590)

This update also fixes several bugs and adds various enhancements.

All kexec-tools users should upgrade to this updated package, which
contains backported patches to resolve these issues and add these
enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=827
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bc3c3e8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kexec-tools and / or kexec-tools-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (rpm_check(release:"SL6", reference:"kexec-tools-2.0.0-209.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kexec-tools-debuginfo-2.0.0-209.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
