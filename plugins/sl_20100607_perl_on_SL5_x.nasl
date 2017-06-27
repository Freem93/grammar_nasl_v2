#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60801);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2008-5302", "CVE-2008-5303", "CVE-2010-1168", "CVE-2010-1447");

  script_name(english:"Scientific Linux Security Update : perl on SL5.x i386/x86_64");
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
"Perl is a high-level programming language commonly used for system
administration utilities and web programming. The Safe extension
module allows users to compile and execute Perl code in restricted
compartments. The File::Path module allows users to create and remove
directory trees.

The Safe module did not properly restrict the code of implicitly
called methods (such as DESTROY and AUTOLOAD) on implicitly blessed
objects returned as a result of unsafe code evaluation. These methods
could have been executed unrestricted by Safe when such objects were
accessed or destroyed. A specially crafted Perl script executed inside
of a Safe compartment could use this flaw to bypass intended Safe
module restrictions. (CVE-2010-1168)

The Safe module did not properly restrict code compiled in a Safe
compartment and executed out of the compartment via a subroutine
reference returned as a result of unsafe code evaluation. A specially
crafted Perl script executed inside of a Safe compartment could use
this flaw to bypass intended Safe module restrictions, if the returned
subroutine reference was called from outside of the compartment.
(CVE-2010-1447)

Multiple race conditions were found in the way the File::Path module's
rmtree function removed directory trees. A malicious, local user with
write access to a directory being removed by a victim, running a Perl
script using rmtree, could cause the permissions of arbitrary files to
be changed to world-writable and setuid, or delete arbitrary files via
a symbolic link attack, if the victim had the privileges to change the
permissions of the target files or to remove them. (CVE-2008-5302,
CVE-2008-5303)

These packages upgrade the Safe extension module to version 2.27.
Refer to the Safe module's Changes file at the following link for a
full list of changes.
http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes

All applications using the Safe or File::Path modules must be
restarted for this update to take effect.

NOTE: SL 50-52 x86_64 releases originally had a perl.i386 package. It
was taken out of the x86_64 SL5 distribution and is not part of this
security update. If you have one of these earlier SL5 x86_64
distributions and your perl update does not work due to conflicts, you
should do a 'yum remove perl.i386' before doing your update on these
earlier SL 5 x86_64 releases."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=400
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c471bb31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl and / or perl-suidperl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
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
if (rpm_check(release:"SL5", reference:"perl-5.8.8-32.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"perl-suidperl-5.8.8-32.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
