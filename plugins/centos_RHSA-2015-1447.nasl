#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1447 and 
# CentOS Errata and Security Advisory 2015:1447 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85022);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2012-5667", "CVE-2015-1345");
  script_bugtraq_id(57033, 72281);
  script_osvdb_id(88814, 117534);
  script_xref(name:"RHSA", value:"2015:1447");

  script_name(english:"CentOS 6 : grep (CESA-2015:1447)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated grep packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. Common Vulnerability Scoring System (CVSS) base scores, which
give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

The grep utility searches through textual input for lines that contain
a match to a specified pattern and then prints the matching lines. The
GNU grep utilities include grep, egrep, and fgrep.

An integer overflow flaw, leading to a heap-based buffer overflow, was
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
directory hierarchies. (BZ#982215, BZ#1064668, BZ#1126757, BZ#1167766,
BZ#1171806)

This update also fixes the following bugs :

* Prior to this update, the \w and \W symbols were inconsistently
matched to the [:alnum:] character class. Consequently, regular
expressions that used \ w and \W in some cases had incorrect results.
An upstream patch which fixes the matching problem has been applied,
and \w is now matched to the [_[:alnum:]] character and \W to the
[^_[:alnum:]] character consistently. (BZ#799863)

* Previously, the '--fixed-regexp' command-line option was not
included in the grep(1) manual page. Consequently, the manual page was
inconsistent with the built-in help of the grep utility. To fix this
bug, grep(1) has been updated to include a note informing the user
that '--fixed-regexp' is an obsolete option. Now, the built-in help
and manual page are consistent regarding the '--fixed-regexp' option.
(BZ#1103270)

* Previously, the Perl Compatible Regular Expression (PCRE) library
did not work correctly when matching non-UTF-8 text in UTF-8 mode.
Consequently, an error message about invalid UTF-8 byte sequence
characters was returned. To fix this bug, patches from upstream have
been applied to the PCRE library and the grep utility. As a result,
PCRE now skips non-UTF-8 characters as non-matching text without
returning any error message. (BZ#1193030)

All grep users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/001936.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d9e4b2b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected grep package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:grep");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"grep-2.20-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
