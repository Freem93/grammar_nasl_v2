#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61142);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/06 13:45:35 $");

  script_cve_id("CVE-2011-3364");

  script_name(english:"Scientific Linux Security Update : NetworkManager on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NetworkManager is a network link manager that attempts to keep a wired
or

wireless network connection active at all times. The ifcfg-rh

NetworkManager plug-in is used in Scientific Linux distributions to

read and write configuration information from the

/etc/sysconfig/network-scripts/ifcfg-* files.

An input sanitization flaw was found in the way the ifcfg-rh
NetworkManager

plug-in escaped network connection names containing special
characters. If

PolicyKit was configured to allow local, unprivileged users to create
and

save new network connections, they could create a connection with a

specially crafted name, leading to the escalation of their privileges.

Note: By default, PolicyKit prevents unprivileged users from creating
and

saving network connections. (CVE-2011-3364)

Users of NetworkManager should upgrade to these updated packages,
which

contain a backported patch to correct this issue. Running instances of

NetworkManager must be restarted ('service NetworkManager restart')
for

this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=3340
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5bd51a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"NetworkManager-0.8.1-9.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"NetworkManager-debuginfo-0.8.1-9.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"NetworkManager-devel-0.8.1-9.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"NetworkManager-glib-0.8.1-9.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"NetworkManager-glib-devel-0.8.1-9.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"NetworkManager-gnome-0.8.1-9.el6_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
