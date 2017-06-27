#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0125 and 
# Oracle Linux Security Advisory ELSA-2013-0125 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68696);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291");
  script_bugtraq_id(48066, 49071, 50486, 51368, 51710, 55035);
  script_osvdb_id(72976, 72977, 72979, 74731, 76770, 78256, 78258, 78656, 78657, 84776, 84780, 84786, 84788);
  script_xref(name:"RHSA", value:"2013:0125");

  script_name(english:"Oracle Linux 5 : wireshark (ELSA-2013-0125)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0125 :

Updated wireshark packages that fix several security issues, three
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
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003198.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"wireshark-1.0.15-5.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"wireshark-gnome-1.0.15-5.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
