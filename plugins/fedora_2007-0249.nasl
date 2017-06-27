#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-0249.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(27656);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:28 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_xref(name:"FEDORA", value:"2007-0249");

  script_name(english:"Fedora 7 : php-pear-DB-1.7.11-1.fc7 (2007-0249)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"1.7.11 : fbsql :

  - Fixed commit and rollback to specify the handle to be
    used.

1.7.10 : mysqli :

  - Added a type map for BIT fields.

1.7.9 : sybase :

  - Added divide by zero error mapping.

    - Added a specific quoteFloat() implementation along the
      same lines as fbsql.

    - Updated tableInfo() to cope with old versions of ASE
      that don't have sp_helpindex.

1.7.8 : DB :

  - Added code to DB_result::numRows() to return correct
    results when limit emulation is being used.

  - Added DB::getDSNString() to allow pretty-printing of
    both string and array DSNs, thereby improving the output
    of DB::connect() on error.

  - Added DB_common::nextQueryIsManip() to explicitly hint
    that the next query is a manipulation query and
    therefore ignore DB::isManip()

  - Changed all freeResult() methods to check that the
    parameter is a resource before calling the native
    function to free the result.

  - Fixed DB_result::fetch*() to only increment their
    internal row_counters when a row number has not been
    provided.

  - Fixed quoting of float values to always have the decimal
    point as a point, rather than a comma, irrespective of
    locale.

  - Silenced errors on ini_set calls.

    - Tweaked DB::isManip() to attempt to deal with SELECT
      queries that include the word INTO in a non-keyword
      context.

fbsql :

  - Fix DB_result::numRows() to return the correct value for
    limit queries.

ibase :

  - Handled cases where ibase_prepare returns false.

ifx :

  - Altered simpleQuery() to treat EXECUTE queries as being
    data-returning.

mssql :

  - Altered nextId() to use IDENT_CURRENT instead of
    @@IDENTITY, thereby resolving problems with concurrent
    nextId() calls.

mysqli :

  - Added the mysterious 246 data type to the type map.

    - Allowed the ssl option to be an integer

oci8 :

  - Added tracking of prepared queries to ensure that
    last_query is set properly even when there are multiple
    prepared queries at a given time.

    - Altered connect() to handle non-standard ports.

    - Altered numRows() to properly restore last_query
      state.

pgsql :

  - Added schema support to _pgFieldFlags.

    - Updated pgsql escaping to use pg_escape_string when
      available.

1.7.7 : DB :

  - added ability to specify port number when using unix
    sockets in DB::parseDSN()

odbc(access) :

  - Tweak quoteSmart() to allows MS Access to wrap dates in
    #'s.

dbase :

  - Added DB_dbase::freeResult().

ifx :

  - Added support for error codes as at Informix 10.

msql :

  - Fix error mapping in PHP 5.2.

mssql :

  - Use mssql_fetch_assoc() instead of mssql_fetch_array().

    - Fix issues with delimited identifiers in mssql
      tableInfo().

    - Added support for some of the key error codes
      introduced in SQL Server 2005.

mysql :

  - fixed handling of fully qualified table names in
    tableInfo().

    - Added support for new error codes in MySQL 5.

mysqli :

  - worked around an issue in 'len' handling of tableInfo().
    There is a bug in ext/mysqli or the mysqli docs.

    - Added support for new error codes in MySQL 5.

oci8 :

  - Allowed old-style functions to use the database DSN
    field if hostspec isn't provided.

pgsql :

  - When inserting to non-existent column, produce proper
    error, 'no such field', instead of 'no such table'.

  - If connection is lost, raise DB_ERROR_CONNECT_FAILED
    instead of the generic DB_ERROR.

  - Allow FETCH queries to return results.

sqlite :

  - Fix bug sqlite:///:memory: trys to open file.

    - Fix error mapping in PHP 5.2.

sybase :

  - Allow connecting without specifying db name.

    - Fix error mapping in PHP 5.2.

storage :

  - Eliminate 'Undefined index $vars' notice in store()

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-June/001839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?652b49a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-DB package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-DB");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"php-pear-DB-1.7.11-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-DB");
}
