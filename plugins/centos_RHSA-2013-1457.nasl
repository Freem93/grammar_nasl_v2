#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1457 and 
# CentOS Errata and Security Advisory 2013:1457 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70633);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-4242");
  script_bugtraq_id(61464);
  script_osvdb_id(95657);
  script_xref(name:"RHSA", value:"2013:1457");

  script_name(english:"CentOS 5 / 6 : libgcrypt (CESA-2013:1457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated libgcrypt package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libgcrypt library provides general-purpose implementations of
various cryptographic algorithms.

It was found that GnuPG was vulnerable to the Yarom/Falkner
flush+reload cache side-channel attack on the RSA secret exponent. An
attacker able to execute a process on the logical CPU that shared the
L3 cache with the GnuPG process (such as a different local user or a
user of a KVM guest running on the same host with the kernel same-page
merging functionality enabled) could possibly use this flaw to obtain
portions of the RSA secret key. (CVE-2013-4242)

All libgcrypt users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-October/019988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b65964c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-October/019992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a775d9ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libgcrypt-1.4.4-7.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libgcrypt-devel-1.4.4-7.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libgcrypt-1.4.5-11.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libgcrypt-devel-1.4.5-11.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
