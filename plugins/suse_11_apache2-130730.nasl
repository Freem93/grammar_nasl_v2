#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69474);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:41:51 $");

  script_cve_id("CVE-2013-1862", "CVE-2013-1896");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : Apache2 (SAT Patch Numbers 8137 / 8138)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update for Apache provides the following fixes :

  - Make sure that input that has already arrived on the
    socket is not discarded during a non-blocking read
    (read(2) returns 0 and errno is set to -EAGAIN).
    (bnc#815621)

  - Close the connection just before an attempted
    re-negotiation if data has been read with pipelining.
    This is done by resetting the keepalive status.
    (bnc#815621)

  - Reset the renegotiation status of a client<->server
    connection to RENEG_INIT to prevent falsely assumed
    status. (bnc#791794)

  - 'OPTIONS *' internal requests are intercepted by a dummy
    filter that kicks in for the OPTIONS method. Apple
    iPrint uses 'OPTIONS *' to upgrade the connection to
    TLS/1.0 following RFC 2817. For compatibility, check if
    an Upgrade request header is present and skip the filter
    if yes. (bnc#791794)

  - Sending a MERGE request against a URI handled by
    mod_dav_svn with the source href (sent as part of the
    request body as XML) pointing to a URI that is not
    configured for DAV will trigger a segfault. (bnc#829056,
    CVE-2013-1896)

  - Client data written to the RewriteLog must have terminal
    escape sequences escaped. (bnc#829057, CVE-2013-1862)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1896.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8137 / 8138 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-doc-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-example-pages-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-prefork-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-utils-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-worker-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-doc-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-example-pages-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-prefork-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-utils-2.2.12-1.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"apache2-worker-2.2.12-1.40.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
