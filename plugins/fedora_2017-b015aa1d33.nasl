#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-b015aa1d33.
#

include("compat.inc");

if (description)
{
  script_id(96676);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2016-7586", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7599", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656");
  script_xref(name:"FEDORA", value:"2017-b015aa1d33");

  script_name(english:"Fedora 25 : webkitgtk4 (2017-b015aa1d33)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update addresses the following vulnerabilities :

  -
    [CVE-2016-7656](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7656),
    [CVE-2016-7635](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7635),
    [CVE-2016-7654](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7654),
    [CVE-2016-7639](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7639),
    [CVE-2016-7645](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7645),
    [CVE-2016-7652](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7652),
    [CVE-2016-7641](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7641),
    [CVE-2016-7632](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7632),
    [CVE-2016-7599](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7599),
    [CVE-2016-7592](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7592),
    [CVE-2016-7589](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7589),
    [CVE-2016-7623](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7623),
    [CVE-2016-7586](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2016-7586)

Additional fixes :

  - Create GLX OpenGL contexts using version 3.2 (core
    profile) when available to reduce the memory consumption
    on Mesa based drivers.

  - Improve memory pressure handler to reduce the CPU usage
    on memory pressure situations.

  - Fix a regression in WebKitWebView title notify signal
    emission that caused the signal to be emitted multiple
    times.

  - Fix high CPU usage in the web process loading
    hyphenation dictionaries. More user agent string
    improvements to improve compatibility with several
    websites.

  - Fix web process crash when closing the web view in X11.

  - Fix the build with OpenGL ES2 enabled.

  - Fix several crashes and rendering issues.

Translation updates :

  - German.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-b015aa1d33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"webkitgtk4-2.14.3-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4");
}
