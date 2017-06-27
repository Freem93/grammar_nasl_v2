#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-17400.
#

include("compat.inc");

if (description)
{
  script_id(57389);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/20 22:05:52 $");

  script_bugtraq_id(51133, 51134, 51135, 51136, 51137, 51138, 51139);
  script_xref(name:"FEDORA", value:"2011-17400");

  script_name(english:"Fedora 16 : firefox-9.0-3.fc16 / nss-3.13.1-9.fc16 / nss-softokn-3.13.1-14.fc16 / etc (2011-17400)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The latest version of Firefox and Thunderbird have the following
changes :

  - Added Type Inference, significantly improving JavaScript
    performance

    - Added support for querying Do Not Track status via
      JavaScript

    - Added support for font-stretch

    - Improved support for text-overflow

    - Improved standards support for HTML5, MathML, and CSS

    - Fixed several stability issues

    - Fixed several security issues

Update nss to 3.13.1

You can find the new features and bug fixes in NSS 3.13 and 3.13.1
with these Bugzilla queries :

https://bugzilla.mozilla.org/buglist.cgi?list_id=1496878&resolution=FI
XED&classification=Components&query_format=advanced&target_milestone=3
.13&product=NSS

and

https://bugzilla.mozilla.org/buglist.cgi?list_id=1496878&resolution=FI
XED&classification=Components&query_format=advanced&target_milestone=3
.13.1&product=NSS

Notable changes include :

1. SSL 2.0 is disabled by default.

2. A defense against the SSL 3.0 and TLS 1.0 CBC chosen plaintext
attack demonstrated by Rizzo and Duong (CVE-2011-3389) is enabled by
default. Set the SSL_CBC_RANDOM_IV SSL option to PR_FALSE to disable
it.

3. SHA-224 is supported.

4. Added PORT_ErrorToString and PORT_ErrorToName to return the error
message and symbolic name of an NSS error code.

5. Added NSS_GetVersion to return the NSS version string.

6. Added experimental support of RSA-PSS to the softoken only
(contributed by Hanno Bock, http://rsapss.hboeck.de/).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rsapss.hboeck.de/"
  );
  # https://bugzilla.mozilla.org/buglist.cgi?list_id=1496878&resolution=FIXED&classification=Components&query_format=advanced&target_milestone=3.13&product=NSS
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c50d6ac0"
  );
  # https://bugzilla.mozilla.org/buglist.cgi?list_id=1496878&resolution=FIXED&classification=Components&query_format=advanced&target_milestone=3.13.1&product=NSS
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?132ae2a7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fa18268"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92f4593c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6791be1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05d0db8f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b974e724"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af682fa6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01c5fc18"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"firefox-9.0-3.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"nss-3.13.1-9.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"nss-softokn-3.13.1-14.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"nss-util-3.13.1-3.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"thunderbird-9.0-4.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"thunderbird-lightning-1.1-0.1.rc1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"xulrunner-9.0-2.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nss / nss-softokn / nss-util / thunderbird / etc");
}
