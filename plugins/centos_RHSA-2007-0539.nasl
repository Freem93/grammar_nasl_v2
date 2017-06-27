#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0539 and 
# CentOS Errata and Security Advisory 2007:0539 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43645);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/28 23:45:05 $");

  script_cve_id("CVE-2007-3849");
  script_osvdb_id(40439);
  script_xref(name:"RHSA", value:"2007:0539");

  script_name(english:"CentOS 5 : aide (CESA-2007:0539)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated aide package that fixes various bugs is now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Advanced Intrusion Detection Environment (AIDE) is a file integrity
checker and intrusion detection program.

A flaw was discovered in the way file checksums were stored in the
AIDE database. A packaging flaw in the Red Hat AIDE rpm resulted in
the file database not containing any file checksum information. This
could prevent AIDE from detecting certain file modifications.
(CVE-2007-3849)

This update also fixes the following bugs :

* certain configurations could result in a segmentation fault upon
initialization.

* AIDE was unable to open its log file in the LSPP evaluated
configuration.

* if AIDE found SELinux context differences, the changed files report
it generated only included the first 32 characters of the context.

All users of AIDE are advised to upgrade to this updated package
containing AIDE version 0.13.1 which is not vulnerable to these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23581ff8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff4185ba"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected aide package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:aide");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"aide-0.13.1-2.0.4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
