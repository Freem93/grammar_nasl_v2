#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1098 and 
# CentOS Errata and Security Advisory 2012:1098 respectively.
#

include("compat.inc");

if (description)
{
  script_id(60066);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406");
  script_bugtraq_id(54374);
  script_osvdb_id(88150);
  script_xref(name:"RHSA", value:"2012:1098");

  script_name(english:"CentOS 6 : glibc (CESA-2012:1098)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix three security issues and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages provide the standard C and standard math libraries
used by multiple programs on the system. Without these libraries, the
Linux system cannot function properly.

Multiple errors in glibc's formatted printing functionality could
allow an attacker to bypass FORTIFY_SOURCE protections and execute
arbitrary code using a format string flaw in an application, even
though these protections are expected to limit the impact of such
flaws to an application abort. (CVE-2012-3404, CVE-2012-3405,
CVE-2012-3406)

This update also fixes the following bug :

* A programming error caused an internal array of nameservers to be
only partially initialized when the /etc/resolv.conf file contained
IPv6 nameservers. Depending on the contents of a nearby structure,
this could cause certain applications to terminate unexpectedly with a
segmentation fault. The programming error has been fixed, which
restores proper behavior with IPv6 nameservers listed in the
/etc/resolv.conf file. (BZ#837026)

All users of glibc are advised to upgrade to these updated packages,
which contain backported patches to fix these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e610099c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"glibc-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-common-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-devel-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-headers-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-static-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-utils-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nscd-2.12-1.80.el6_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
