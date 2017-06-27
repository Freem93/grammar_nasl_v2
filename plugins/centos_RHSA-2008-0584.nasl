#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0584 and 
# CentOS Errata and Security Advisory 2008:0584 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33449);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-2927");
  script_osvdb_id(46838, 48330);
  script_xref(name:"RHSA", value:"2008:0584");

  script_name(english:"CentOS 3 / 4 / 5 : pidgin (CESA-2008:0584)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Pidgin packages that fix a security issue and address a bug
are now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Pidgin is a multi-protocol Internet Messaging client.

An integer overflow flaw was found in Pidgin's MSN protocol handler.
If a user received a malicious MSN message, it was possible to execute
arbitrary code with the permissions of the user running Pidgin.
(CVE-2008-2927)

Note: the default Pidgin privacy setting only allows messages from
users in the buddy list. This prevents arbitrary MSN users from
exploiting this flaw.

This update also addresses the following bug :

* when attempting to connect to the ICQ network, Pidgin would fail to
connect, present an alert saying the 'The client version you are using
is too old', and de-activate the ICQ account. This update restores
Pidgin's ability to connect to the ICQ network.

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b50937"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abef8324"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4caf2ac2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f819e0b7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c654c91"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d0c3d77"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4fd11c8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a887d4ef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"pidgin-1.5.1-2.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"pidgin-1.5.1-2.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.3.1-2.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
