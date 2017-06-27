#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0266 and 
# CentOS Errata and Security Advisory 2006:0266 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21990);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0049", "CVE-2006-0455");
  script_osvdb_id(23221, 23790);
  script_xref(name:"RHSA", value:"2006:0266");

  script_name(english:"CentOS 3 / 4 : gnu / gnupg (CESA-2006:0266)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated GnuPG package that fixes signature verification flaws as
well as minor bugs is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

Tavis Ormandy discovered a bug in the way GnuPG verifies
cryptographically signed data with detached signatures. It is possible
for an attacker to construct a cryptographically signed message which
could appear to come from a third party. When a victim processes a
GnuPG message with a malformed detached signature, GnuPG ignores the
malformed signature, processes and outputs the signed data, and exits
with status 0, just as it would if the signature had been valid. In
this case, GnuPG's exit status would not indicate that no signature
verification had taken place. This issue would primarily be of concern
when processing GnuPG results via an automated script. The Common
Vulnerabilities and Exposures project assigned the name CVE-2006-0455
to this issue.

Tavis Ormandy also discovered a bug in the way GnuPG verifies
cryptographically signed data with inline signatures. It is possible
for an attacker to inject unsigned data into a signed message in such
a way that when a victim processes the message to recover the data,
the unsigned data is output along with the signed data, gaining the
appearance of having been signed. This issue is mitigated in the GnuPG
shipped with Red Hat Enterprise Linux as the --ignore-crc-error option
must be passed to the gpg executable for this attack to be successful.
The Common Vulnerabilities and Exposures project assigned the name
CVE-2006-0049 to this issue.

Please note that neither of these issues affect the way RPM or up2date
verify RPM package files, nor is RPM vulnerable to either of these
issues.

All users of GnuPG are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5099b54e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65fcd15d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c8f0d72"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?568c0bb1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnu and / or gnupg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"gnupg-1.2.1-15")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnupg-1.2.6-3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
