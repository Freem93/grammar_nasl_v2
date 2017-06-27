#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-3095.
#

include("compat.inc");

if (description)
{
  script_id(79758);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:35:11 $");

  script_cve_id("CVE-2014-6407", "CVE-2014-6408");

  script_name(english:"Oracle Linux 6 / 7 : docker (ELSA-2014-3095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[1.3.2-1.0.1]
- Rename requirement of docker-io-pkg-devel in %package devel as 
docker-pkg-devel
- Rename as docker
- Restore SysV init scripts for Oracle Linux 6

[1.3.2-1]
- Update source to 1.3.2 from 
https://github.com/docker/docker/releases/tag/v1.3.2
   Prevent host privilege escalation from an image extraction 
vulnerability (CVE-2014-6407).
   Prevent container escalation from malicious security options applied 
to images (CVE-2014-6408).
   The `--insecure-registry` flag of the `docker run` command has 
undergone several refinements and additions.
   You can now specify a sub-net in order to set a range of registries 
which the Docker daemon will consider insecure.
   By default, Docker now defines `localhost` as an insecure registry.
   Registries can now be referenced using the Classless Inter-Domain 
Routing (CIDR) format.
   When mirroring is enabled, the experimental registry v2 API is skipped.

[1.3.1-2]
- Remove pandoc from build reqs

[1.3.1-1]
- update to v1.3.1

[1.3.0-1]
- Resolves: rhbz#1153936 - update to v1.3.0
- don't install zsh files
- iptables=false => ip-masq=false

[1.2.0-5]
- Resolves: rhbz#1149882 - systemd unit and socket file updates

[1.2.0-4]
- Resolves: rhbz#1139415 - correct path for bash completion
     /usr/share/bash-completion/completions
- versioned provides for docker
- golang versioned requirements for devel and pkg-devel
- remove macros from changelog
- don't own dirs owned by vim, systemd, bash

[1.2.0-3]
- Resolves: rhbz#1145660 - support /etc/sysconfig/docker-storage
   From: Colin Walters <<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>walters at redhat.com</A>>
- patch to ignore selinux if it's disabled
https://github.com/docker/docker/commit/9e2eb0f1cc3c4ef000e139f1d85a20f0e00971e6
   From: Dan Walsh <<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>dwalsh at redhat.com</A>>

[1.2.0-2]
- Provides docker only for f21 and above

[1.2.0-1]
- Resolves: rhbz#1132824 - update to v1.2.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-December/004694.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-December/004695.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:docker-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-1.3.2-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-devel-1.3.2-1.0.1.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"docker-pkg-devel-1.3.2-1.0.1.el6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-1.3.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-devel-1.3.2-1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"docker-pkg-devel-1.3.2-1.0.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-devel / docker-pkg-devel");
}
