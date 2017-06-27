#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6048.
#

include("compat.inc");

if (description)
{
  script_id(33411);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_cve_id("CVE-2008-2371");
  script_xref(name:"FEDORA", value:"2008-6048");

  script_name(english:"Fedora 9 : glib2-2.16.4-1.fc9 (2008-6048)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"><i>From the release announcement: * Update to PCRE 7.7 - fix a
heap-based </I>buffer overflow in PCRE (CVE-2008-2371) * Bug fixes:
528752 Win32 build and SSL not working 539074 Cannot get exit status
with g_spawn_command_line_sync() 316221 G_LOCK warns about breaking
strict-aliasing rules 519137 g_slice_dup macro needs cast for 64-bit
platform 536158 also bump GHashTable version when a node is removed
via g_hash_table_iter_remove()/g_hash_table_iter_steal() 529321 make
check fails in glib/pcre 314453 Nautilus crashes in Solaris when
browsing the attached file 502511 g_assert_cmphex prints invalid
message 538119 glib's mainloop leaks a pipe to sub-processes 540459
there are no way of getting the real number of bytes written in
GMemoryOutputStream 540423 unrecoverable error after
g_seekable_truncate(seekable,0,...) 530196
_g_local_file_has_trash_dir() doesn't handle st_dev == 0 528600
g_dummy_file_get_parent('scheme://example.com/') 536641 Filesystem
querying in gio does not list AFS and autofs file systems 537392
Additional colon in xattr name 528433 gdesktopappinfo snafu ... 526320
should not list mounts that the user doesn't have permiss... 527132
nautilus crash when making ftp connection 532852
totem_pl_parser_parse_with_base: assertion `... 459905 Bug in wcwidth
data 534085 g_unichar_iswide_cjk() has a totally wrong table * Updated
translations: Bulgarian (bg) German (de)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452079"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97a20446"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glib2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"glib2-2.16.4-1.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2");
}
