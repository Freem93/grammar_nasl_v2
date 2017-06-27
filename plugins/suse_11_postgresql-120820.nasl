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
  script_id(64216);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");

  script_name(english:"SuSE 11.1 Security Update : PostgreSQL (SAT Patch Number 6697)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides PostgreSQL 8.3.20. As part of this update, the
packaging scheme has been changed to accomodate an optional parallel
installation of newer PostgreSQL versions.

The changes in 8.3.20 are :

  - Prevent access to external files/URLs via XML entity
    references. xml_parse() would attempt to fetch external
    files or URLs as needed to resolve DTD and entity
    references in an XML value, thus allowing unprivileged
    database users to attempt to fetch data with the
    privileges of the database server. (CVE-2012-3489,
    bnc#776524)

  - Prevent access to external files/URLs via
    'contrib/xml2''s xslt_process(). libxslt offers the
    ability to read and write both files and URLs through
    stylesheet commands, thus allowing unprivileged database
    users to both read and write data with the privileges of
    the database server. Disable that through proper use of
    libxslt's security options. (CVE-2012-3488, bnc#776523).
    Also, remove xslt_process()'s ability to fetch documents
    and stylesheets from external files/URLs.

  - Fix incorrect password transformation in
    contrib/pgcrypto's DES crypt() function. If a password
    string contained the byte value 0x80, the remainder of
    the password was ignored, causing the password to be
    much weaker than it appeared. With this fix, the rest of
    the string is properly included in the DES hash. Any
    stored password values that are affected by this bug
    will thus no longer match, so the stored values may need
    to be updated. (CVE-2012-2143)

  - Ignore SECURITY DEFINER and SET attributes for a
    procedural language's call handler. Applying such
    attributes to a call handler could crash the server.
    (CVE-2012-2655)

  - Allow numeric timezone offsets in timestamp input to be
    up to 16 hours away from UTC. Some historical time zones
    have offsets larger than 15 hours, the previous limit.
    This could result in dumped data values being rejected
    during reload.

  - Fix timestamp conversion to cope when the given time is
    exactly the last DST transition time for the current
    timezone. This oversight has been there a long time, but
    was not noticed previously because most DST-using zones
    are presumed to have an indefinite sequence of future
    DST transitions.

  - Fix text to name and char to name casts to perform
    string truncation correctly in multibyte encodings.

  - Fix memory copying bug in to_tsquery().

  - Fix slow session startup when pg_attribute is very
    large. If pg_attribute exceeds one-fourth of
    shared_buffers, cache rebuilding code that is sometimes
    needed during session start would trigger the
    synchronized-scan logic, causing it to take many times
    longer than normal. The problem was particularly acute
    if many new sessions were starting at once.

  - Ensure sequential scans check for query cancel
    reasonably often. A scan encountering many consecutive
    pages that contain no live tuples would not respond to
    interrupts meanwhile.

  - Show whole-row variables safely when printing views or
    rules. Corner cases involving ambiguous names (that is,
    the name could be either a table or column name of the
    query) were printed in an ambiguous way, risking that
    the view or rule would be interpreted differently after
    dump and reload. Avoid the ambiguous case by attaching a
    no-op cast.

  - Ensure autovacuum worker processes perform stack depth
    checking properly. Previously, infinite recursion in a
    function invoked by auto-ANALYZE could crash worker
    processes.

  - Fix logging collector to not lose log coherency under
    high load. The collector previously could fail to
    reassemble large messages if it got too busy.

  - Fix logging collector to ensure it will restart file
    rotation after receiving SIGHUP.

  - Fix PL/pgSQL's GET DIAGNOSTICS command when the target
    is the function's first variable.

  - Fix several performance problems in pg_dump when the
    database contains many objects. pg_dump could get very
    slow if the database contained many schemas, or if many
    objects are in dependency loops, or if there are many
    owned sequences.

  - Fix contrib/dblink's dblink_exec() to not leak temporary
    database connections upon error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3489.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6697.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"postgresql-8.3.20-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"postgresql-init-9.1-0.6.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"postgresql-8.3.20-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"postgresql-init-9.1-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-8.3.20-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-contrib-8.3.20-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-docs-8.3.20-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-init-9.1-0.6.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-server-8.3.20-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
