#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85194);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2012-5667", "CVE-2015-1345");

  script_name(english:"Scientific Linux Security Update : grep on SL6.x i386/x86_64");
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
"An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way grep parsed large lines of data. An attacker able to
trick a user into running grep on a specially crafted data file could
use this flaw to crash grep or, potentially, execute arbitrary code
with the privileges of the user running grep. (CVE-2012-5667)

A heap-based buffer overflow flaw was found in the way grep processed
certain pattern and text combinations. An attacker able to trick a
user into running grep on specially crafted input could use this flaw
to crash grep or, potentially, read from uninitialized memory.
(CVE-2015-1345)

The grep packages have been upgraded to upstream version 2.20, which
provides a number of bug fixes and enhancements over the previous
version. Notably, the speed of various operations has been improved
significantly. Now, the recursive grep utility uses the fts function
of the gnulib library for directory traversal, so that it can handle
much larger directories without reporting the 'File name too long'
error message, and it can operate faster when dealing with large
directory hierarchies.

This update also fixes the following bugs :

  - Prior to this update, the \w and \W symbols were
    inconsistently matched to the [:alnum:] character class.
    Consequently, regular expressions that used \w and \W in
    some cases had incorrect results. An upstream patch
    which fixes the matching problem has been applied, and
    \w is now matched to the [_[:alnum:]] character and \W
    to the [^_[:alnum:]] character consistently.

  - Previously, the '--fixed-regexp' command-line option was
    not included in the grep(1) manual page. Consequently,
    the manual page was inconsistent with the built-in help
    of the grep utility. To fix this bug, grep(1) has been
    updated to include a note informing the user that
    '--fixed-regexp' is an obsolete option. Now, the
    built-in help and manual page are consistent regarding
    the '--fixed-regexp' option.

  - Previously, the Perl Compatible Regular Expression
    (PCRE) library did not work correctly when matching
    non-UTF-8 text in UTF-8 mode. Consequently, an error
    message about invalid UTF-8 byte sequence characters was
    returned. To fix this bug, patches from upstream have
    been applied to the PCRE library and the grep utility.
    As a result, PCRE now skips non-UTF-8 characters as
    non-matching text without returning any error message."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=3964
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c1cf3b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected grep and / or grep-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"grep-2.20-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"grep-debuginfo-2.20-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
