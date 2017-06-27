#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2713.
#

include("compat.inc");

if (description)
{
  script_id(27795);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2007-5623");
  script_bugtraq_id(26215);
  script_xref(name:"FEDORA", value:"2007-2713");

  script_name(english:"Fedora 7 : nagios-plugins-1.4.8-9.fc7 (2007-2713)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Oct 26 2007 Mike McGrath <mmcgrath at redhat.com>
    1.4.8-9

    - Fix for Bug 348731 and CVE-2007-5623

    - Wed Aug 22 2007 Mike McGrath <mmcgrath at redhat.com>
      1.4.8-7

    - Rebuild for BuildID

    - License change

    - Fri Aug 10 2007 Mike McGrath <mmcgrath at redhat.com>
      1.4.8-6

    - Fix for check_linux_raid - #234416

    - Fix for check_ide_disk - #251635

    - Tue Aug 7 2007 Mike McGrath <mmcgrath at redhat.com>
      1.4.8-2

    - Fix for check_smtp - #251049

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=348731"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75b4df62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-by_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-dig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-disk_smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-file_age");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-flexlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-fping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-game");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-hpjd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-icmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ide_smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ifoperstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ifstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ircd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-linux_raid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-mrtg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-mrtgtraf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-nt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-nwstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-overcr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-procs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-real");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-rpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-swap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-tcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-udp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-ups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-users");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nagios-plugins-wave");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"nagios-plugins-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-all-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-apt-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-breeze-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-by_ssh-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-debuginfo-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-dhcp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-dig-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-disk-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-disk_smb-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-dns-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-dummy-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-file_age-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-flexlm-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-fping-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-game-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-hpjd-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-http-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-icmp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ide_smart-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ifoperstatus-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ifstatus-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ircd-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ldap-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-linux_raid-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-load-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-log-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-mailq-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-mrtg-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-mrtgtraf-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-mysql-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-nagios-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-nt-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ntp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-nwstat-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-oracle-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-overcr-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-perl-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-pgsql-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ping-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-procs-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-radius-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-real-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-rpc-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-sensors-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-smtp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-snmp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ssh-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-swap-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-tcp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-time-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-udp-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-ups-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-users-1.4.8-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"nagios-plugins-wave-1.4.8-9.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios-plugins / nagios-plugins-all / nagios-plugins-apt / etc");
}
