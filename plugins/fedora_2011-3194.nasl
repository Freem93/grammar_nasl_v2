#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-3194.
#

include("compat.inc");

if (description)
{
  script_id(52696);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:05:53 $");

  script_cve_id("CVE-2011-0064");
  script_bugtraq_id(46632);
  script_osvdb_id(71247);
  script_xref(name:"FEDORA", value:"2011-3194");

  script_name(english:"Fedora 14 : pango-1.28.1-5.fc14 (2011-3194)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that pango did not check for memory reallocation
failures in hb_buffer_ensure() function. This could trigger a NULL
pointer dereference in hb_buffer_add_glyph(), where possibly untrusted
input is used as an index used for accessing members of the
incorrectly reallocated array, resulting in the use of NULL address as
the base array address. This can result in application crash or,
possibly, code execution.

It was demonstrated that it's possible to trigger this flaw in Firefox
via a specially crafted web page.

Mozilla bug report (currently not public):
https://bugzilla.mozilla.org/show_bug.cgi?id=606997

Fix in the harfbuzz git:
http://cgit.freedesktop.org/harfbuzz/commit/?id=a6a79df5fe2e

Acknowledgements :

Red Hat would like to thank Mozilla Security Team for reporting this
issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cgit.freedesktop.org/harfbuzz/commit/?id=a6a79df5fe2e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=606997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=678563"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/056065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33a0389"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pango package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pango");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"pango-1.28.1-5.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pango");
}
