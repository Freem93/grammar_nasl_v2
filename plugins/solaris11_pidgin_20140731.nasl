#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80740);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6486", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");

  script_name(english:"Oracle Solaris Third-Party Patch Update : pidgin (multiple_vulnerabilities_in_pidgin2)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - The Yahoo! protocol plugin in libpurple in Pidgin before
    2.10.8 does not properly validate UTF-8 data, which
    allows remote attackers to cause a denial of service
    (application crash) via crafted byte sequences.
    (CVE-2012-6152)

  - The MXit protocol plugin in libpurple in Pidgin before
    2.10.7 might allow remote attackers to create or
    overwrite files via a crafted (1) mxit or (2)
    mxit/imagestrips pathname. (CVE-2013-0271)

  - Buffer overflow in http.c in the MXit protocol plugin in
    libpurple in Pidgin before 2.10.7 allows remote servers
    to execute arbitrary code via a long HTTP header.
    (CVE-2013-0272)

  - sametime.c in the Sametime protocol plugin in libpurple
    in Pidgin before 2.10.7 does not properly terminate long
    user IDs, which allows remote servers to cause a denial
    of service (application crash) via a crafted packet.
    (CVE-2013-0273)

  - upnp.c in libpurple in Pidgin before 2.10.7 does not
    properly terminate long strings in UPnP responses, which
    allows remote attackers to cause a denial of service
    (application crash) by leveraging access to the local
    network. (CVE-2013-0274)

  - Multiple integer signedness errors in libpurple in
    Pidgin before 2.10.8 allow remote attackers to cause a
    denial of service (application crash) via a crafted
    timestamp value in an XMPP message. (CVE-2013-6477)

  - gtkimhtml.c in Pidgin before 2.10.8 does not properly
    interact with underlying library support for wide Pango
    layouts, which allows user-assisted remote attackers to
    cause a denial of service (application crash) via a long
    URL that is examined with a tooltip. (CVE-2013-6478)

  - util.c in libpurple in Pidgin before 2.10.8 does not
    properly allocate memory for HTTP responses that are
    inconsistent with the Content-Length header, which
    allows remote HTTP servers to cause a denial of service
    (application crash) via a crafted response.
    (CVE-2013-6479)

  - libpurple/protocols/yahoo/libymsg.c in Pidgin before
    2.10.8 allows remote attackers to cause a denial of
    service (crash) via a Yahoo! P2P message with a crafted
    length field, which triggers a buffer over-read.
    (CVE-2013-6481)

  - Pidgin before 2.10.8 allows remote MSN servers to cause
    a denial of service (NULL pointer dereference and crash)
    via a crafted (1) SOAP response, (2) OIM XML response,
    or (3) Content-Length header. (CVE-2013-6482)

  - The XMPP protocol plugin in libpurple in Pidgin before
    2.10.8 does not properly determine whether the from
    address in an iq reply is consistent with the to address
    in an iq request, which allows remote attackers to spoof
    iq traffic or cause a denial of service (NULL pointer
    dereference and application crash) via a crafted reply.
    (CVE-2013-6483)

  - The STUN protocol implementation in libpurple in Pidgin
    before 2.10.8 allows remote STUN servers to cause a
    denial of service (out-of-bounds write operation and
    application crash) by triggering a socket read error.
    (CVE-2013-6484)

  - Buffer overflow in util.c in libpurple in Pidgin before
    2.10.8 allows remote HTTP servers to cause a denial of
    service (application crash) or possibly have unspecified
    other impact via an invalid chunk-size field in chunked
    transfer-coding data. (CVE-2013-6485)

  - gtkutils.c in Pidgin before 2.10.8 on Windows allows
    user-assisted remote attackers to execute arbitrary
    programs via a message containing a file: URL that is
    improperly handled during construction of an
    explorer.exe command. NOTE: this vulnerability exists
    because of an incomplete fix for CVE-2011-3185.
    (CVE-2013-6486)

  - Integer overflow in libpurple/protocols/gg/lib/http.c in
    the Gadu-Gadu (gg) parser in Pidgin before 2.10.8 allows
    remote attackers to have an unspecified impact via a
    large Content-Length value, which triggers a buffer
    overflow. (CVE-2013-6487)

  - Integer signedness error in the MXit functionality in
    Pidgin before 2.10.8 allows remote attackers to cause a
    denial of service (segmentation fault) via a crafted
    emoticon value, which triggers an integer overflow and a
    buffer overflow. (CVE-2013-6489)

  - The SIMPLE protocol functionality in Pidgin before
    2.10.8 allows remote attackers to have an unspecified
    impact via a negative Content-Length header, which
    triggers a buffer overflow. (CVE-2013-6490)

  - The IRC protocol plugin in libpurple in Pidgin before
    2.10.8 does not validate argument counts, which allows
    remote IRC servers to cause a denial of service
    (application crash) via a crafted message.
    (CVE-2014-0020)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_pidgin2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9e548b3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:pidgin");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^pidgin$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.0.0.0.0", sru:"11.2 SRU 0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : pidgin\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "pidgin");
