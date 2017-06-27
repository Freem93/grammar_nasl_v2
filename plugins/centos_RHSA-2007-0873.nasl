#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0873 and 
# CentOS Errata and Security Advisory 2007:0873 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25972);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-4134");
  script_bugtraq_id(25417);
  script_osvdb_id(39576);
  script_xref(name:"RHSA", value:"2007:0873");

  script_name(english:"CentOS 3 / 4 / 5 : star (CESA-2007:0873)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated star package that fixes a path traversal flaw is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Star is a tar-like archiver. It saves multiple files into a single
tape or disk archive, and can restore individual files from the
archive. Star includes multi-volume support, automatic archive format
detection and ACL support.

A path traversal flaw was discovered in the way star extracted
archives. A malicious user could create a tar archive that would cause
star to write to arbitrary files to which the user running star had
write access. (CVE-2007-4134)

Red Hat would like to thank Robert Buchholz for reporting this issue.

As well, this update adds the command line argument '-..' to the Red
Hat Enterprise Linux 3 version of star. This allows star to extract
files containing '/../' in their pathname.

Users of star should upgrade to this updated package, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d17f681"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40889cad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c8bfef0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014169.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03886a1c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dff68bd7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?830c7087"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da1ef460"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7023090c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected star package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:star");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"star-1.5a08-5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"star-1.5a25-8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"star-1.5a75-2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
