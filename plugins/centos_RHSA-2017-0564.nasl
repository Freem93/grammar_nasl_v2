#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0564 and 
# CentOS Errata and Security Advisory 2017:0564 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97949);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:41 $");

  script_cve_id("CVE-2015-8869");
  script_osvdb_id(137809);
  script_xref(name:"RHSA", value:"2017:0564");

  script_name(english:"CentOS 6 : libguestfs (CESA-2017:0564)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libguestfs is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libguestfs packages contain a library, which is used for accessing
and modifying virtual machine (VM) disk images.

Security Fix(es) :

* An integer conversion flaw was found in the way OCaml's String
handled its length. Certain operations on an excessively long String
could trigger a buffer overflow or result in an information leak.
(CVE-2015-8869)

Note: The libguestfs packages in this advisory were rebuilt with a
fixed version of OCaml to address this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2017-March/003822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdc4b50e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libguestfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-devel-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-java-devel-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-javadoc-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libguestfs-tools-c-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"python-libguestfs-1.20.11-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"ruby-libguestfs-1.20.11-20.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
