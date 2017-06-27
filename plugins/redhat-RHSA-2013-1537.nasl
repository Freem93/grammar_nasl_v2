#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1537. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71000);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-0786", "CVE-2012-0787", "CVE-2012-6607");
  script_osvdb_id(100076);
  script_xref(name:"RHSA", value:"2013:1537");

  script_name(english:"RHEL 6 : augeas (RHSA-2013:1537)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated augeas packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Augeas is a utility for editing configuration. Augeas parses
configuration files in their native formats and transforms them into a
tree. Configuration changes are made by manipulating this tree and
saving it back into native configuration files. Augeas also uses
'lenses' as basic building blocks for establishing the mapping from
files into the Augeas tree and back.

Multiple flaws were found in the way Augeas handled configuration
files when updating them. An application using Augeas to update
configuration files in a directory that is writable to by a different
user (for example, an application running as root that is updating
files in a directory owned by a non-root service user) could have been
tricked into overwriting arbitrary files or leaking information via a
symbolic link or mount point attack. (CVE-2012-0786, CVE-2012-0787)

The augeas package has been upgraded to upstream version 1.0.0, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#817753)

This update also fixes the following bugs :

* Previously, when single quotes were used in an XML attribute, Augeas
was unable to parse the file with the XML lens. An upstream patch has
been provided ensuring that single quotes are handled as valid
characters and parsing no longer fails. (BZ#799885)

* Prior to this update, Augeas was unable to set up the
'require_ssl_reuse' option in the vsftpd.conf file. The updated patch
fixes the vsftpd lens to properly recognize this option, thus fixing
this bug. (BZ#855022)

* Previously, the XML lens did not support non-Unix line endings.
Consequently, Augeas was unable to load any files containing such line
endings. The XML lens has been fixed to handle files with CRLF line
endings, thus fixing this bug. (BZ#799879)

* Previously, Augeas was unable to parse modprobe.conf files with
spaces around '=' characters in option directives. The modprobe lens
has been updated and parsing no longer fails. (BZ#826752)

All Augeas users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0787.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1537.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:augeas-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:augeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:augeas-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1537";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"augeas-1.0.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"augeas-1.0.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"augeas-1.0.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"augeas-debuginfo-1.0.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"augeas-devel-1.0.0-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"augeas-libs-1.0.0-5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "augeas / augeas-debuginfo / augeas-devel / augeas-libs");
  }
}
