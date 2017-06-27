#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0154 and 
# Oracle Linux Security Advisory ELSA-2010-0154 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68015);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-1571", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2466", "CVE-2009-2470", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3274", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3384", "CVE-2009-3979", "CVE-2010-0159", "CVE-2010-0163", "CVE-2010-0169", "CVE-2010-0171");
  script_bugtraq_id(35765, 35769, 35776, 36343, 36851, 36852, 36867, 36871, 37361, 38286, 38287);
  script_osvdb_id(55603, 57972, 57976, 57977, 57978, 61091, 61186, 61187, 61188, 61189, 62402);
  script_xref(name:"RHSA", value:"2010:0154");

  script_name(english:"Oracle Linux 4 : thunderbird (ELSA-2010-0154)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0154 :

An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-2462,
CVE-2009-2463, CVE-2009-2466, CVE-2009-3072, CVE-2009-3075,
CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)

A use-after-free flaw was found in Thunderbird. An attacker could use
this flaw to crash Thunderbird or, potentially, execute arbitrary code
with the privileges of the user running Thunderbird. (CVE-2009-3077)

A heap-based buffer overflow flaw was found in the Thunderbird string
to floating point conversion routines. An HTML mail message containing
malicious JavaScript could crash Thunderbird or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2009-0689)

A use-after-free flaw was found in Thunderbird. Under low memory
conditions, viewing an HTML mail message containing malicious content
could result in Thunderbird executing arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-1571)

A flaw was found in the way Thunderbird created temporary file names
for downloaded files. If a local attacker knows the name of a file
Thunderbird is going to download, they can replace the contents of
that file with arbitrary contents. (CVE-2009-3274)

A flaw was found in the way Thunderbird displayed a right-to-left
override character when downloading a file. In these cases, the name
displayed in the title bar differed from the name displayed in the
dialog body. An attacker could use this flaw to trick a user into
downloading a file that has a file name or extension that is different
from what the user expected. (CVE-2009-3376)

A flaw was found in the way Thunderbird processed SOCKS5 proxy
replies. A malicious SOCKS5 server could send a specially crafted
reply that would cause Thunderbird to crash. (CVE-2009-2470)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing trusted
content or, potentially, execute arbitrary code with the privileges of
the user running Thunderbird. (CVE-2009-3076)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-March/001396.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"thunderbird-1.5.0.12-25.0.1.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
