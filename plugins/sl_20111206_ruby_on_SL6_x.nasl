#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61197);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-2686");

  script_name(english:"Scientific Linux Security Update : ruby on SL6.x i386/x86_64");
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
"Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

It was found that Ruby did not reinitialize the PRNG (pseudorandom
number generator) after forking a child process. This could eventually
lead to the PRNG returning the same result twice. An attacker keeping
track of the values returned by one child process could use this flaw
to predict the values the PRNG would return in other child processes
(as long as the parent process persisted). (CVE-2011-3009)

A flaw was found in the Ruby SecureRandom module. When using the
SecureRandom.random_bytes class, the PRNG state was not modified after
forking a child process. This could eventually lead to
SecureRandom.random_bytes returning the same string more than once. An
attacker keeping track of the strings returned by one child process
could use this flaw to predict the strings SecureRandom.random_bytes
would return in other child processes (as long as the parent process
persisted). (CVE-2011-2705)

This update also fixes the following bugs :

  - The ruby package has been upgraded to upstream point
    release 1.8.7-p352, which provides a number of bug fixes
    over the previous version.

  - The MD5 message-digest algorithm is not a FIPS-approved
    algorithm. Consequently, when a Ruby script attempted to
    calculate an MD5 checksum in FIPS mode, the interpreter
    terminated unexpectedly. This bug has been fixed and an
    exception is now raised in the described scenario.

  - Due to inappropriately handled line continuations in the
    mkconfig.rb source file, an attempt to build the ruby
    package resulted in unexpected termination. An upstream
    patch has been applied to address this issue and the
    ruby package can now be built properly.

  - When the 32-bit ruby-libs library was installed on a
    64-bit machine, the mkmf library failed to load various
    modules necessary for building Ruby-related packages.
    This bug has been fixed and mkmf now works properly in
    the described scenario.

  - Previously, the load paths for scripts and binary
    modules were duplicated on the i386 architecture.
    Consequently, an ActiveSupport test failed. With this
    update, the load paths are no longer stored in
    duplicates on the i386 architecture.

This update also adds the following enhancement :

  - With this update, SystemTap probes have been added to
    the ruby package.

All users of ruby are advised to upgrade to these updated packages,
which resolve these issues and add this enhancement."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=1448
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e809406f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (rpm_check(release:"SL6", reference:"ruby-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-debuginfo-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-devel-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-docs-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-irb-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-libs-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-rdoc-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-ri-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-static-1.8.7.352-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-tcltk-1.8.7.352-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
