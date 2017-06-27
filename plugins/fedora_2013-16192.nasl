#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-16192.
#

include("compat.inc");

if (description)
{
  script_id(69964);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_bugtraq_id(61976);
  script_xref(name:"FEDORA", value:"2013-16192");

  script_name(english:"Fedora 18 : roundcubemail-0.9.4-1.fc18 (2013-16192)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"0.9.4, latest upstream. Require webserver rather than httpd. Two XSS
flaws were fixed in roundcube 0.9.3 [1] :

  - Fix XSS vulnerability when saving HTML signatures
    [2],[3]

    - Fix XSS vulnerability when editing a message 'as new'
      or draft [2],[4]

[1] http://trac.roundcube.net/wiki/Changelog#RELEASE0.9.3 [2]
http://trac.roundcube.net/ticket/1489251 [3]
http://trac.roundcube.net/changeset/ce5a6496fd6039962ba7424d153278e41a
e8761b/github [4]
http://trac.roundcube.net/changeset/93b0a30c1c8aa29d862b587b31e52bcc34
4b8d16/github

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://trac.roundcube.net/changeset/93b0a30c1c8aa29d862b587b31e52bcc344b8d16/github
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76c8cd72"
  );
  # http://trac.roundcube.net/changeset/ce5a6496fd6039962ba7424d153278e41ae8761b/github
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6233b6f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/ticket/1489251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/wiki/Changelog#RELEASE0.9.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1000511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1000512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1005696"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af8c77b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"roundcubemail-0.9.4-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
