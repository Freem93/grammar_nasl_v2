#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0125. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63408);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291");
  script_bugtraq_id(48066, 49071, 50486, 51368, 51710, 55035);
  script_osvdb_id(72976, 72977, 72979, 74731, 76770, 78256, 78258, 78656, 78657, 84776, 84780, 84786, 84788);
  script_xref(name:"RHSA", value:"2013:0125");

  script_name(english:"RHEL 5 : wireshark (RHSA-2013:0125)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues, three
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Wireshark, previously known as Ethereal, is a network protocol
analyzer. It is used to capture and browse the traffic running on a
computer network.

A heap-based buffer overflow flaw was found in the way Wireshark
handled Endace ERF (Extensible Record Format) capture files. If
Wireshark opened a specially crafted ERF capture file, it could crash
or, possibly, execute arbitrary code as the user running Wireshark.
(CVE-2011-4102)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2011-1958,
CVE-2011-1959, CVE-2011-2175, CVE-2011-2698, CVE-2012-0041,
CVE-2012-0042, CVE-2012-0066, CVE-2012-0067, CVE-2012-4285,
CVE-2012-4289, CVE-2012-4290, CVE-2012-4291)

The CVE-2011-1958, CVE-2011-1959, CVE-2011-2175, and CVE-2011-4102
issues were discovered by Huzaifa Sidhpurwala of the Red Hat Security
Response Team.

This update also fixes the following bugs :

* When Wireshark starts with the X11 protocol being tunneled through
an SSH connection, it automatically prepares its capture filter to
omit the SSH packets. If the SSH connection was to a link-local IPv6
address including an interface name (for example ssh -X
[ipv6addr]%eth0), Wireshark parsed this address erroneously,
constructed an incorrect capture filter and refused to capture
packets. The 'Invalid capture filter' message was displayed. With this
update, parsing of link-local IPv6 addresses is fixed and Wireshark
correctly prepares a capture filter to omit SSH packets over a
link-local IPv6 connection. (BZ#438473)

* Previously, Wireshark's column editing dialog malformed column names
when they were selected. With this update, the dialog is fixed and no
longer breaks column names. (BZ#493693)

* Previously, TShark, the console packet analyzer, did not properly
analyze the exit code of Dumpcap, Wireshark's packet capturing back
end. As a result, TShark returned exit code 0 when Dumpcap failed to
parse its command-line arguments. In this update, TShark correctly
propagates the Dumpcap exit code and returns a non-zero exit code when
Dumpcap fails. (BZ#580510)

* Previously, the TShark '-s' (snapshot length) option worked only for
a value greater than 68 bytes. If a lower value was specified, TShark
captured just 68 bytes of incoming packets. With this update, the '-s'
option is fixed and sizes lower than 68 bytes work as expected.
(BZ#580513)

This update also adds the following enhancement :

* In this update, support for the 'NetDump' protocol was added.
(BZ#484999)

All users of Wireshark are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement. All running instances of Wireshark must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4290.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0125.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected wireshark, wireshark-debuginfo and / or
wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0125";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-debuginfo-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-debuginfo-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-debuginfo-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-gnome-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-gnome-1.0.15-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-gnome-1.0.15-5.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-gnome");
  }
}
