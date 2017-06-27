#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-5960.
#

include("compat.inc");

if (description)
{
  script_id(73880);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 22:32:19 $");

  script_cve_id("CVE-2014-0185");
  script_bugtraq_id(67118);
  script_xref(name:"FEDORA", value:"2014-5960");

  script_name(english:"Fedora 20 : php-5.5.12-1.fc20 (2014-5960)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Notice: to fix CVE-2014-0185 this version change default php-fpm unix
domain socket permission to 660 (instead of 666). Check your
configuration if php-fpm use UDS (default configuration use a network
socket).

Upstream Changelog: 01 May 2014, PHP 5.5.12 Core :

  - Fixed bug #61019 (Out of memory on command
    stream_get_contents). (Mike)

    - Fixed bug #64330 (stream_socket_server() creates wrong
      Abstract Namespace UNIX sockets). (Mike)

    - Fixed bug #66182 (exit in stream filter produces
      segfault). (Mike)

    - Fixed bug #66736 (fpassthru broken). (Mike)

    - Fixed bug #67024 (getimagesize should recognize BMP
      files with negative height). (Gabor Buella)

    - Fixed bug #67043 (substr_compare broke by previous
      change) (Tjerk)

cURL :

  - Fixed bug #66562 (curl_exec returns differently than
    curl_multi_getcontent). (Freek Lijten)

Date :

  - Fixed bug #66721 (__wakeup of DateTime segfaults when
    invalid object data is supplied). (Boro Sitnikovski)

Embed :

  - Fixed bug #65715 (php5embed.lib isn't provided anymore).
    (Anatol).

Fileinfo :

  - Fixed bug #66987 (Memory corruption in fileinfo ext /
    bigendian). (Remi)

FPM :

  - Fixed bug #66482 (unknown entry 'priority' in
    php-fpm.conf).

    - Fixed bug #67060 (possible privilege escalation due to
      insecure default configuration). (CVE-2014-0185)
      (christian at hoffie dot info)

LDAP :

  - Fixed issue with null bytes in LDAP bindings. (Matthew
    Daley)

mysqli :

  - Fixed problem in mysqli_commit()/mysqli_rollback() with
    second parameter (extra comma) and third parameters
    (lack of escaping). (Andrey)

OpenSSL :

  - Fix bug #66942 (memory leak in openssl_seal()). (Chuan
    Ma)

    - Fix bug #66952 (memory leak in openssl_open()). (Chuan
      Ma)

SimpleXML :

  - Fixed bug #66084 (simplexml_load_string() mangles empty
    node name) (Anatol)

SQLite :

  - Fixed bug #66967 (Updated bundled libsqlite to 3.8.4.3).
    (Anatol)

XSL :

  - Fixed bug #53965 (<xsl:include> cannot find files with
    relative paths when loaded with 'file://'). (Anatol)

Apache2 Handler SAPI :

  - Fixed Apache log issue caused by APR's lack of support
    for %zu (APR issue
    https://issues.apache.org/bugzilla/show_bug.cgi?id=56120
    ). (Jeff Trawick)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1092815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=56120"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d26f6ef2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"php-5.5.12-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
