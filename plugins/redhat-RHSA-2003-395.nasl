#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:395. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12439);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2003-0971");
  script_xref(name:"RHSA", value:"2003:395");

  script_name(english:"RHEL 2.1 / 3 : gnupg (RHSA-2003:395)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnupg packages are now available for Red Hat Enterprise Linux.
These updates disable the ability to generate ElGamal keys (used for
both signing and encrypting) and disable the ability to use ElGamal
public keys for encrypting data.

GnuPG is a utility for encrypting data and creating digital
signatures.

Phong Nguyen identified a severe bug in the way GnuPG creates and uses
ElGamal keys, when those keys are used both to sign and encrypt data.
This vulnerability can be used to trivially recover the private key.
While the default behavior of GnuPG when generating keys does not lead
to the creation of unsafe keys, by overriding the default settings an
unsafe key could have been created.

If you are using ElGamal keys, you should revoke those keys
immediately.

The packages included in this update do not make ElGamal keys safe to
use; they merely include a patch by David Shaw that disables functions
that would generate or use ElGamal keys.

To determine if your key is affected, run the following command to
obtain a list of secret keys that you have on your secret keyring :

gpg --list-secret-keys

The output of this command includes both the size and type of the keys
found, and will look similar to this example :

/home/example/.gnupg/secring.gpg
---------------------------------------------------- sec
1024D/01234567 2000-10-17 Example User <example@example.com> uid
Example User <example@example.com>

The key length, type, and ID are listed together, separated by a
forward slash. In the example output above, the key's type is 'D'
(DSA, sign and encrypt). Your key is unsafe if and only if the key
type is 'G' (ElGamal, sign and encrypt). In the above example, the
secret key is safe to use, while the secret key in the following
example is not :

/home/example/.gnupg/secring.gpg
---------------------------------------------------- sec
1024G/01234567 2000-10-17 Example User <example@example.com> uid
Example User <example@example.com>

For more details regarding this issue, as well as instructions on how
to revoke any keys that are unsafe, refer to the advisory available
from the GnuPG website :

http://www.gnupg.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0971.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-announce/2003q4/000276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-users/2003-November/020779.html"
  );
  # http://lists.gnupg.org/pipermail/gnupg-announce/2003q4/000277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-announce/2003q4/000160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-395.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:395";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gnupg-1.0.7-13")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gnupg-1.2.1-10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg");
  }
}
