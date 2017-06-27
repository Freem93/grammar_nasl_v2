#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-1343.
#

include("compat.inc");

if (description)
{
  script_id(35734);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:41:46 $");

  script_cve_id("CVE-2009-0386", "CVE-2009-0387");
  script_bugtraq_id(33405);
  script_xref(name:"FEDORA", value:"2009-1343");

  script_name(english:"Fedora 9 : gstreamer-plugins-good-0.10.8-10.fc9 (2009-1343)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Feb 2 2009 - Bastien Nocera <bnocera at redhat.com>
    - 0.10.8-10

    - Patch for overflows in the QT demuxer (#481267)

    - Tue Aug 12 2008 Adam Jackson <ajax at redhat.com>
      0.10.8-9

    - gst-plugins-good-0.10.8-http-auth.patch: Fix http
      auth. (#457952)

    - Mon Jul 21 2008 Adam Jackson <ajax at redhat.com>
      0.10.8-8

    - gst-plugins-good-0.10.8-v4l2-progressive-fix.patch:
      Backport v4l2 interlace/progressive fixes. (#454534)

  - Thu Jun 19 2008 Adam Jackson <ajax at redhat.com>
    0.10.8-7

    - gst-plugins-good-0.10.8-speex-nego.patch: Backport
      speex channel and rate negotiation from 0.10.9.
      (#451391)

  - Tue Jun 17 2008 - Bastien Nocera <bnocera at redhat.com>
    - 0.10.8-6

    - Really fix the default audio output not being correct

    - Tue Jun 3 2008 - Bastien Nocera <bnocera at
      redhat.com> - 0.10.8-5

    - Fix compilation of the v4l2 plugin with newer kernels

    - Mon Jun 2 2008 - Bastien Nocera <bnocera at
      redhat.com> - 0.10.8-4

    - Work-around bug that would set the default audio
      output to 'GOOM!' See
      http://bugzilla.gnome.org/show_bug.cgi?id=532295

  - Wed May 21 2008 Tom 'spot' Callaway <tcallawa at
    redhat.com> 0.10.8-3

    - fix license tag

    - Wed May 21 2008 Adam Jackson <ajax at redhat.com>
      0.10.8-2

    - BR: libsoup-devel and package the soup http src
      plugin. (#447604)

    - s/Fedora Core/Fedora/

    - Thu Apr 24 2008 - Bastien Nocera <bnocera at
      redhat.com> - 0.10.8-1

    - Update to 0.10.8

    - Thu Apr 10 2008 - Bastien Nocera <bnocera at
      redhat.com> - 0.10.7-2

    - Add patch to unbreak the QuickTime demuxer plugin

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.gnome.org/show_bug.cgi?id=532295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=481267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483737"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/020564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e39f52cc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-good package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC9", reference:"gstreamer-plugins-good-0.10.8-10.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-good");
}
