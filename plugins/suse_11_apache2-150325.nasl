#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82657);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/26 04:39:25 $");

  script_cve_id("CVE-2003-1418", "CVE-2013-5704", "CVE-2014-3581");

  script_name(english:"SuSE 11.3 Security Update : apache2 (SAT Patch Number 10533)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache2 webserver was updated to fix various issues.

The following feature was added :

  - Provide support for the tunneling of web socket
    connections to a backend websockets server.
    (FATE#316880) The following security issues have been
    fixed :

  - The mod_headers module in the Apache HTTP Server 2.2.22
    allowed remote attackers to bypass 'RequestHeader unset'
    directives by placing a header in the trailer portion of
    data sent with chunked transfer coding. The fix also
    adds a 'MergeTrailers' directive to restore legacy
    behavior. (CVE-2013-5704)

  - The cache_merge_headers_out function in
    modules/cache/cache_util.c in the mod_cache module in
    the Apache HTTP Server allowed remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via an empty HTTP Content-Type
    header. (CVE-2014-3581)

  - Apache HTTP Server allowed remote attackers to obtain
    sensitive information via (1) the ETag header, which
    reveals the inode number, or (2) multipart MIME
    boundary, which reveals child process IDs (PID). We so
    far assumed that this not useful to attackers, the fix
    is basically just reducing potential information leaks.
    (CVE-2003-1418)

The following bugs have been fixed :

  - Treat the 'server unavailable' condition as a transient
    error with all LDAP SDKs. (bsc#904427)

  - Fixed a segmentation fault at startup if the certs are
    shared across > 1 server_rec. (bsc#907339)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2003-1418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3581.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10533.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-2.2.12-1.51.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-doc-2.2.12-1.51.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-example-pages-2.2.12-1.51.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-prefork-2.2.12-1.51.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-utils-2.2.12-1.51.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-worker-2.2.12-1.51.52.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
